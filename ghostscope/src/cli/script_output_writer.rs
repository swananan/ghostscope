//! Bounded output delivery independent of the tracing and signal tasks.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

const CHUNK_BYTES: usize = 64 * 1024;
const QUEUED_CHUNKS: usize = 8;

pub(super) struct ScriptOutputWriter {
    sender: Option<mpsc::Sender<Vec<u8>>>,
    completed: oneshot::Receiver<io::Result<()>>,
    cancelled: Arc<AtomicBool>,
}

impl ScriptOutputWriter {
    pub(super) fn stdout() -> io::Result<Self> {
        // Own a duplicate descriptor, never StdoutLock: Rust's exit-time stdout
        // cleanup must remain free to run while a pipe write is blocked.
        let fd = io::stdout().as_fd().try_clone_to_owned()?;
        Self::new(File::from(fd))
    }

    pub(super) fn stderr() -> io::Result<Self> {
        let fd = io::stderr().as_fd().try_clone_to_owned()?;
        Self::new(File::from(fd))
    }

    fn new(mut writer: impl Write + Send + 'static) -> io::Result<Self> {
        let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(QUEUED_CHUNKS);
        let (done, completed) = oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        // A dedicated thread owns only this descriptor and bounded byte chunks.
        // Blocking OS writes cannot be cancelled. Do not put them in Tokio's
        // blocking pool, whose shutdown waits for outstanding writes to finish.
        std::thread::Builder::new()
            .name("ghostscope-output".into())
            .spawn(move || {
                let result = (|| {
                    while let Some(bytes) = receiver.blocking_recv() {
                        if worker_cancelled.load(Ordering::Acquire) {
                            return Ok(());
                        }
                        writer.write_all(&bytes)?;
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
        })
    }

    /// Backpressure is asynchronous and cancellable by the caller's signal select.
    /// The queue holds at most 512 KiB, plus one chunk in the blocking writer.
    pub(super) async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        for chunk in bytes.chunks(CHUNK_BYTES) {
            if self
                .sender
                .as_ref()
                .expect("output sender is present until drop")
                .send(chunk.to_vec())
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
    pub(super) async fn finish(mut self) -> io::Result<()> {
        self.sender.take();
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
