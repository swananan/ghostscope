//! Bounded output delivery independent of the tracing and signal tasks.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

const CHUNK_BYTES: usize = 64 * 1024;
const QUEUED_CHUNKS: usize = 8;

enum OutputMessage {
    Bytes(Vec<u8>),
    Finish,
}

pub(crate) struct ScriptOutputWriter {
    sender: Option<mpsc::Sender<OutputMessage>>,
    completed: oneshot::Receiver<io::Result<()>>,
    cancelled: Arc<AtomicBool>,
    dropped_log_chunks: Arc<AtomicU64>,
}

/// Console logging cannot await backpressure on the tracing task. Keep its
/// best-effort queue bounded and report skipped chunks when output resumes.
#[derive(Clone)]
pub(crate) struct NonBlockingLogWriter {
    sender: mpsc::Sender<OutputMessage>,
    dropped: Arc<AtomicU64>,
}

impl Write for NonBlockingLogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for chunk in bytes.chunks(CHUNK_BYTES) {
            if let Err(mpsc::error::TrySendError::Full(_)) =
                self.sender.try_send(OutputMessage::Bytes(chunk.to_vec()))
            {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ScriptOutputWriter {
    pub(super) fn stdout() -> io::Result<Self> {
        // Own a duplicate descriptor, never StdoutLock: Rust's exit-time stdout
        // cleanup must remain free to run while a pipe write is blocked.
        let fd = io::stdout().as_fd().try_clone_to_owned()?;
        Self::new(File::from(fd))
    }

    pub(crate) fn stderr() -> io::Result<Self> {
        let fd = io::stderr().as_fd().try_clone_to_owned()?;
        Self::new(File::from(fd))
    }

    fn new(mut writer: impl Write + Send + 'static) -> io::Result<Self> {
        let (sender, mut receiver) = mpsc::channel(QUEUED_CHUNKS);
        let (done, completed) = oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let dropped_log_chunks = Arc::new(AtomicU64::new(0));
        let worker_dropped = Arc::clone(&dropped_log_chunks);
        // A dedicated thread owns only this descriptor and bounded byte chunks.
        // Blocking OS writes cannot be cancelled. Do not put them in Tokio's
        // blocking pool, whose shutdown waits for outstanding writes to finish.
        std::thread::Builder::new()
            .name("ghostscope-output".into())
            .spawn(move || {
                let result = (|| {
                    while let Some(message) = receiver.blocking_recv() {
                        if worker_cancelled.load(Ordering::Acquire) {
                            return Ok(());
                        }
                        let dropped = worker_dropped.swap(0, Ordering::Relaxed);
                        if dropped > 0 {
                            writeln!(writer, "ghostscope: console log output saturated: dropped {dropped} chunks")?;
                        }
                        match message {
                            OutputMessage::Bytes(bytes) => writer.write_all(&bytes)?,
                            OutputMessage::Finish => break,
                        }
                    }
                    if !worker_cancelled.load(Ordering::Acquire) {
                        writer.flush()?;
                    }
                    Ok(())
                })();
                let _ = done.send(result);
            })?;
        Ok(Self {
            sender: Some(sender),
            completed,
            cancelled,
            dropped_log_chunks,
        })
    }

    pub(crate) fn non_blocking_log_writer(&self) -> NonBlockingLogWriter {
        NonBlockingLogWriter {
            sender: self
                .sender
                .as_ref()
                .expect("output sender is present until drop")
                .clone(),
            dropped: Arc::clone(&self.dropped_log_chunks),
        }
    }

    /// Backpressure is asynchronous and cancellable by the caller's signal select.
    /// The queue holds at most 512 KiB, plus one chunk in the blocking writer.
    pub(super) async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        for chunk in bytes.chunks(CHUNK_BYTES) {
            if self
                .sender
                .as_ref()
                .expect("output sender is present until drop")
                .send(OutputMessage::Bytes(chunk.to_vec()))
                .await
                .is_err()
            {
                return self.completed().await;
            }
        }
        Ok(())
    }

    pub(super) async fn completed(&mut self) -> io::Result<()> {
        (&mut self.completed)
            .await
            .map_err(|_| io::Error::other("script output worker stopped unexpectedly"))?
    }

    /// Deliver accepted chunks and close the descriptor. The caller must impose
    /// a deadline: cancelling this future falls back to the non-blocking Drop.
    pub(crate) async fn finish(mut self) -> io::Result<()> {
        // Logging subscribers can retain sender clones for the process lifetime.
        // An explicit end marker lets the owner drain and close them anyway.
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(OutputMessage::Finish).await;
        }
        self.completed().await
    }
}

impl Drop for ScriptOutputWriter {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.sender.take();
        // Do not join a thread that may be blocked in the consumer's pipe.
        // Session teardown releases all probes independently of this writer.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    struct PausedWriter {
        started: Option<oneshot::Sender<()>>,
        release: std::sync::mpsc::Receiver<()>,
        bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl Write for PausedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
                self.release.recv().unwrap();
            }
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn full_queue_is_cancellable_and_console_loss_is_reported() {
        let (started, blocked) = oneshot::channel();
        let (release, receiver) = std::sync::mpsc::channel();
        let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut output = ScriptOutputWriter::new(PausedWriter {
            started: Some(started),
            release: receiver,
            bytes: Arc::clone(&bytes),
        })
        .unwrap();
        let mut console = output.non_blocking_log_writer();
        output.write(b"first\n").await.unwrap();
        blocked.await.unwrap();
        output
            .write(&vec![b'x'; CHUNK_BYTES * QUEUED_CHUNKS])
            .await
            .unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            output.write(b"cancelled\n"),
        )
        .await;
        assert!(
            result.is_err(),
            "the full queue must await capacity asynchronously"
        );
        console.write_all(b"dropped console message\n").unwrap();
        release.send(()).unwrap();
        // The subscriber's live sender clone must not hold graceful finish open.
        tokio::time::timeout(std::time::Duration::from_secs(2), output.finish())
            .await
            .expect("healthy consumers must finish even with a live subscriber")
            .unwrap();
        let bytes = bytes.lock().unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("console log output saturated: dropped 1 chunks"));
        assert!(!text.contains("cancelled"));
        assert!(!text.contains("dropped console message"));
        assert_eq!(
            bytes.iter().filter(|byte| **byte == b'x').count(),
            CHUNK_BYTES * QUEUED_CHUNKS
        );
    }

    #[tokio::test]
    async fn finish_delivers_console_logs_with_a_live_subscriber() {
        let (writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let mut reader = tokio::net::UnixStream::from_std(reader).unwrap();
        let output = ScriptOutputWriter::new(writer).unwrap();
        let mut console = output.non_blocking_log_writer();
        console.write_all(b"console warning\n").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), output.finish())
            .await
            .expect("a subscriber clone must not keep the worker alive")
            .unwrap();
        let mut received = String::new();
        reader.read_to_string(&mut received).await.unwrap();
        assert_eq!(received, "console warning\n");
    }

    #[tokio::test]
    async fn graceful_finish_delivers_all_queued_output() {
        let (writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let mut reader = tokio::net::UnixStream::from_std(reader).unwrap();
        let mut output = ScriptOutputWriter::new(writer).unwrap();
        let expected: Vec<u8> = (0..CHUNK_BYTES * QUEUED_CHUNKS)
            .map(|index| (index % 251) as u8)
            .collect();
        // Accept a full queue before allowing the consumer to read it.
        output.write(&expected).await.unwrap();
        let received = tokio::spawn(async move {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();
            bytes
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), output.finish())
            .await
            .expect("a healthy consumer must drain during shutdown")
            .unwrap();
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), received)
            .await
            .expect("the worker must close its descriptor after draining")
            .unwrap();
        assert_eq!(
            received.len(),
            expected.len(),
            "shutdown lost accepted output"
        );
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn finish_propagates_non_pipe_write_failures() {
        let writer = File::options().write(true).open("/dev/full").unwrap();
        let mut output = ScriptOutputWriter::new(writer).unwrap();
        output.write(b"event\n").await.unwrap();
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), output.finish())
            .await
            .expect("a failed writer must finish shutdown")
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
    }

    #[tokio::test]
    async fn closed_consumer_notifies_the_control_task() {
        let (writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(reader);
        let mut output = ScriptOutputWriter::new(writer).unwrap();
        output.write(b"event\n").await.unwrap();
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), output.completed())
            .await
            .expect("a failed writer must wake the control task")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
}
