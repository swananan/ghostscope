//! Async debuginfod client.
//!
//! This crate implements the small HTTP client-side subset GhostScope needs:
//! debuginfo, executable, and source lookups by build-id. It does not implement
//! a debuginfod server.
//!
//! The HTTP paths implemented here come from the debuginfod web API documented
//! by elfutils/debuginfod(8):
//! <https://sourceware.org/elfutils/Debuginfod.html>
//! and distro man pages such as:
//! <https://manpages.ubuntu.com/manpages/noble/en/man8/debuginfod.8.html>.

use futures_util::StreamExt;
use reqwest::{StatusCode, Url};
use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{fs, io::AsyncWriteExt};

pub const DEFAULT_TIMEOUT_SECS: u64 = 5;

const USER_AGENT: &str = concat!("ghostscope/", env!("CARGO_PKG_VERSION"));

pub type Result<T> = std::result::Result<T, DebuginfodError>;

#[derive(Debug, Error)]
pub enum DebuginfodError {
    #[error("invalid debuginfod URL '{raw}': {source}")]
    InvalidUrl {
        raw: String,
        source: url::ParseError,
    },

    #[error("unsupported debuginfod URL scheme '{scheme}' in '{raw}'")]
    UnsupportedUrlScheme { raw: String, scheme: String },

    #[error("invalid build-id: build-id must not be empty")]
    EmptyBuildId,

    #[error("invalid source path '{0}': debuginfod source queries require an absolute path")]
    InvalidSourcePath(String),

    #[error("debuginfod HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("I/O error for {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("debuginfod response exceeded configured maximum size ({max_size} bytes)")]
    ResponseTooLarge { max_size: u64 },
}

#[derive(Debug, Clone)]
pub struct DebuginfodConfig {
    urls: Vec<Url>,
    cache_dir: PathBuf,
    timeout: Option<Duration>,
    max_size: Option<u64>,
    user_agent: String,
}

impl DebuginfodConfig {
    pub fn new<I, S>(urls: I, cache_dir: impl Into<PathBuf>) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let urls = parse_url_list(urls)?;
        Ok(Self {
            urls,
            cache_dir: cache_dir.into(),
            timeout: Some(Duration::from_secs(DEFAULT_TIMEOUT_SECS)),
            max_size: None,
            user_agent: USER_AGENT.to_string(),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn without_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    pub fn with_max_size(mut self, max_size: Option<u64>) -> Self {
        self.max_size = max_size.filter(|size| *size > 0);
        self
    }

    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    pub fn urls(&self) -> &[Url] {
        &self.urls
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    pub fn max_size(&self) -> Option<u64> {
        self.max_size
    }
}

#[derive(Debug, Clone)]
pub struct DebuginfodClient {
    config: DebuginfodConfig,
    http: reqwest::Client,
}

impl DebuginfodClient {
    pub fn new(config: DebuginfodConfig) -> Result<Self> {
        let mut builder = reqwest::Client::builder().user_agent(config.user_agent.clone());
        if let Some(timeout) = config.timeout {
            builder = builder.timeout(timeout);
        }
        let http = builder.build()?;
        Ok(Self { config, http })
    }

    pub fn config(&self) -> &DebuginfodConfig {
        &self.config
    }

    pub async fn fetch_debuginfo(&self, build_id: &[u8]) -> Result<Option<FetchedFile>> {
        self.fetch_artifact(build_id, Artifact::Debuginfo).await
    }

    pub async fn fetch_executable(&self, build_id: &[u8]) -> Result<Option<FetchedFile>> {
        self.fetch_artifact(build_id, Artifact::Executable).await
    }

    pub async fn fetch_source(
        &self,
        build_id: &[u8],
        source_path: impl AsRef<str>,
    ) -> Result<Option<FetchedFile>> {
        self.fetch_artifact(
            build_id,
            Artifact::Source {
                path: source_path.as_ref(),
            },
        )
        .await
    }

    async fn fetch_artifact(
        &self,
        build_id: &[u8],
        artifact: Artifact<'_>,
    ) -> Result<Option<FetchedFile>> {
        if build_id.is_empty() {
            return Err(DebuginfodError::EmptyBuildId);
        }

        let build_id_hex = build_id_to_hex(build_id);
        let cache_path = artifact.cache_path(self.config.cache_dir(), &build_id_hex)?;
        if fs::metadata(&cache_path).await.is_ok() {
            return Ok(Some(FetchedFile {
                path: cache_path,
                build_id: build_id_hex,
                from_cache: true,
                url: None,
            }));
        }

        let endpoint = artifact.endpoint_path(&build_id_hex)?;
        for base_url in self.config.urls() {
            let url = build_url(base_url, &endpoint)?;
            tracing::debug!(%url, "querying debuginfod");

            let response = match self.http.get(url.clone()).send().await {
                Ok(response) => response,
                Err(err) => {
                    tracing::warn!(%url, error=%err, "debuginfod request failed");
                    continue;
                }
            };

            match response.status() {
                StatusCode::OK => {
                    match stream_response_to_cache(response, &cache_path, self.config.max_size())
                        .await
                    {
                        Ok(()) => {
                            return Ok(Some(FetchedFile {
                                path: cache_path,
                                build_id: build_id_hex,
                                from_cache: false,
                                url: Some(url.to_string()),
                            }));
                        }
                        Err(DebuginfodError::Http(err)) => {
                            tracing::warn!(%url, error=%err, "debuginfod response download failed");
                            continue;
                        }
                        Err(err) => return Err(err),
                    }
                }
                StatusCode::NOT_FOUND => {
                    tracing::debug!(%url, "debuginfod artifact not found");
                }
                status => {
                    tracing::warn!(%url, %status, "debuginfod returned non-success status");
                }
            }
        }

        Ok(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedFile {
    pub path: PathBuf,
    pub build_id: String,
    pub from_cache: bool,
    pub url: Option<String>,
}

#[derive(Debug, Copy, Clone)]
enum Artifact<'a> {
    Debuginfo,
    Executable,
    Source { path: &'a str },
}

impl Artifact<'_> {
    fn endpoint_path(&self, build_id_hex: &str) -> Result<String> {
        // debuginfod(8) defines:
        //   /buildid/BUILDID/debuginfo
        //   /buildid/BUILDID/executable
        //   /buildid/BUILDID/source/SOURCE/FILE
        // where BUILDID is hexadecimal and SOURCE/FILE should be absolute.
        match self {
            Self::Debuginfo => Ok(format!("/buildid/{build_id_hex}/debuginfo")),
            Self::Executable => Ok(format!("/buildid/{build_id_hex}/executable")),
            Self::Source { path } => Ok(format!(
                "/buildid/{}/source/{}",
                build_id_hex,
                encode_source_path_for_url(path)?
            )),
        }
    }

    fn cache_path(&self, cache_dir: &Path, build_id_hex: &str) -> Result<PathBuf> {
        let build_id_dir = cache_dir.join(build_id_hex);
        match self {
            Self::Debuginfo => Ok(build_id_dir.join("debuginfo")),
            Self::Executable => Ok(build_id_dir.join("executable")),
            Self::Source { path } => source_cache_path(&build_id_dir, path),
        }
    }
}

pub fn build_id_to_hex(build_id: &[u8]) -> String {
    let mut hex = String::with_capacity(build_id.len() * 2);
    for byte in build_id {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

pub fn parse_url_list<I, S>(urls: I) -> Result<Vec<Url>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut parsed = Vec::new();
    for raw in urls {
        let raw = raw.as_ref().trim();
        if raw.is_empty() || raw.starts_with("ima:") {
            continue;
        }

        let mut url = Url::parse(raw).map_err(|source| DebuginfodError::InvalidUrl {
            raw: raw.to_string(),
            source,
        })?;
        match url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(DebuginfodError::UnsupportedUrlScheme {
                    raw: raw.to_string(),
                    scheme: scheme.to_string(),
                });
            }
        }

        url.set_query(None);
        url.set_fragment(None);
        parsed.push(url);
    }
    Ok(parsed)
}

fn build_url(base_url: &Url, endpoint_path: &str) -> Result<Url> {
    let base = base_url.as_str().trim_end_matches('/');
    let endpoint = endpoint_path.trim_start_matches('/');
    let raw = format!("{base}/{endpoint}");
    Url::parse(&raw).map_err(|source| DebuginfodError::InvalidUrl { raw, source })
}

fn encode_source_path_for_url(source_path: &str) -> Result<String> {
    let rest = source_path
        .strip_prefix('/')
        .ok_or_else(|| DebuginfodError::InvalidSourcePath(source_path.to_string()))?;

    if rest.is_empty() {
        return Err(DebuginfodError::InvalidSourcePath(source_path.to_string()));
    }

    // debuginfod(8) says clients should %-escape source path bytes that are not
    // RFC3986 section 2.3 "unreserved" characters. Slash stays unescaped here
    // because the debuginfod endpoint treats SOURCE/FILE as path segments.
    let mut encoded = String::with_capacity(rest.len());
    for byte in rest.bytes() {
        match byte {
            b'/' => encoded.push('/'),
            b if is_unreserved_uri_byte(b) => encoded.push(byte as char),
            b => {
                use std::fmt::Write;
                let _ = write!(&mut encoded, "%{b:02X}");
            }
        }
    }
    Ok(encoded)
}

fn source_cache_path(build_id_dir: &Path, source_path: &str) -> Result<PathBuf> {
    if !source_path.starts_with('/') {
        return Err(DebuginfodError::InvalidSourcePath(source_path.to_string()));
    }

    let mut path = build_id_dir.join("source");
    let mut saw_component = false;
    for component in Path::new(source_path).components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                path.push(encode_path_component(part));
                saw_component = true;
            }
            Component::CurDir => {
                path.push("%2E");
                saw_component = true;
            }
            Component::ParentDir => {
                path.push("%2E%2E");
                saw_component = true;
            }
            Component::Prefix(_) => {
                return Err(DebuginfodError::InvalidSourcePath(source_path.to_string()));
            }
        }
    }

    if !saw_component {
        return Err(DebuginfodError::InvalidSourcePath(source_path.to_string()));
    }

    Ok(path)
}

#[cfg(unix)]
fn encode_path_component(component: &OsStr) -> String {
    use std::os::unix::ffi::OsStrExt;
    percent_encode_component(component.as_bytes())
}

#[cfg(not(unix))]
fn encode_path_component(component: &OsStr) -> String {
    percent_encode_component(component.to_string_lossy().as_bytes())
}

fn percent_encode_component(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len());
    for &byte in bytes {
        if is_unreserved_uri_byte(byte) {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write;
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn is_unreserved_uri_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
    )
}

async fn stream_response_to_cache(
    response: reqwest::Response,
    cache_path: &Path,
    max_size: Option<u64>,
) -> Result<()> {
    if let Some(max_size) = max_size {
        if response
            .content_length()
            .is_some_and(|content_length| content_length > max_size)
        {
            return Err(DebuginfodError::ResponseTooLarge { max_size });
        }
    }

    let parent = cache_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .await
        .map_err(|source| DebuginfodError::Io {
            path: parent.to_path_buf(),
            source,
        })?;

    let tmp_path = temporary_path(cache_path);
    let result = write_stream_to_file(response, &tmp_path, max_size).await;
    if let Err(error) = result {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(error);
    }

    fs::rename(&tmp_path, cache_path)
        .await
        .map_err(|source| DebuginfodError::Io {
            path: cache_path.to_path_buf(),
            source,
        })?;
    Ok(())
}

async fn write_stream_to_file(
    response: reqwest::Response,
    tmp_path: &Path,
    max_size: Option<u64>,
) -> Result<()> {
    let mut file = fs::File::create(tmp_path)
        .await
        .map_err(|source| DebuginfodError::Io {
            path: tmp_path.to_path_buf(),
            source,
        })?;
    let mut stream = response.bytes_stream();
    let mut total = 0_u64;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        total = total.saturating_add(chunk.len() as u64);
        if let Some(max_size) = max_size {
            if total > max_size {
                return Err(DebuginfodError::ResponseTooLarge { max_size });
            }
        }
        file.write_all(&chunk)
            .await
            .map_err(|source| DebuginfodError::Io {
                path: tmp_path.to_path_buf(),
                source,
            })?;
    }

    file.flush().await.map_err(|source| DebuginfodError::Io {
        path: tmp_path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn temporary_path(cache_path: &Path) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let filename = cache_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("debuginfod");
    cache_path.with_file_name(format!("{filename}.tmp-{}-{suffix}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tempfile::TempDir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn build_id_hex_is_lowercase() {
        assert_eq!(build_id_to_hex(&[0xab, 0xcd, 0x01, 0xef]), "abcd01ef");
    }

    #[test]
    fn parse_urls_skips_ima_tags_and_trims_fragments() {
        let urls = parse_url_list([
            "https://debuginfod.example/",
            "ima:enforcing",
            "http://localhost:8002/path?ignored=yes#fragment",
        ])
        .unwrap();

        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0].as_str(), "https://debuginfod.example/");
        assert_eq!(urls[1].as_str(), "http://localhost:8002/path");
    }

    #[test]
    fn source_endpoint_percent_encodes_non_unreserved_chars() {
        let endpoint = Artifact::Source {
            path: "/usr/src/foo bar+/main.c",
        }
        .endpoint_path("abc123")
        .unwrap();

        assert_eq!(
            endpoint,
            "/buildid/abc123/source/usr/src/foo%20bar%2B/main.c"
        );
    }

    #[test]
    fn build_url_preserves_already_escaped_source_path() {
        let base = Url::parse("https://debuginfod.example/prefix/").unwrap();
        let endpoint = Artifact::Source {
            path: "/usr/src/foo bar+/main.c",
        }
        .endpoint_path("abc123")
        .unwrap();
        let url = build_url(&base, &endpoint).unwrap();

        assert_eq!(
            url.as_str(),
            "https://debuginfod.example/prefix/buildid/abc123/source/usr/src/foo%20bar%2B/main.c"
        );
    }

    #[test]
    fn source_cache_path_never_uses_parent_dir_components() {
        let path = source_cache_path(Path::new("/cache/abc123"), "/zoo//../bar/foo.c").unwrap();

        assert_eq!(path, Path::new("/cache/abc123/source/zoo/%2E%2E/bar/foo.c"));
    }

    #[test]
    fn source_path_must_be_absolute() {
        let err = Artifact::Source { path: "relative.c" }
            .endpoint_path("abc123")
            .unwrap_err();

        assert!(matches!(err, DebuginfodError::InvalidSourcePath(_)));
    }

    #[tokio::test]
    async fn fetch_debuginfo_downloads_and_reuses_cache() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::clone(&requests);

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.starts_with("GET /buildid/abcd/debuginfo HTTP/1.1"));
            request_count.fetch_add(1, Ordering::SeqCst);

            let body = b"debug-data";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        });

        let cache = TempDir::new().unwrap();
        let config = DebuginfodConfig::new([format!("http://{addr}")], cache.path()).unwrap();
        let client = DebuginfodClient::new(config).unwrap();

        let first = client
            .fetch_debuginfo(&[0xab, 0xcd])
            .await
            .unwrap()
            .unwrap();
        assert!(!first.from_cache);
        assert_eq!(fs::read(&first.path).await.unwrap(), b"debug-data");

        let second = client
            .fetch_debuginfo(&[0xab, 0xcd])
            .await
            .unwrap()
            .unwrap();
        assert!(second.from_cache);
        assert_eq!(first.path, second.path);
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn max_size_rejects_large_response_before_cache_commit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();

            let body = b"too-large";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        });

        let cache = TempDir::new().unwrap();
        let config = DebuginfodConfig::new([format!("http://{addr}")], cache.path())
            .unwrap()
            .with_max_size(Some(4));
        let client = DebuginfodClient::new(config).unwrap();

        let err = client.fetch_debuginfo(&[0xab, 0xcd]).await.unwrap_err();
        assert!(matches!(
            err,
            DebuginfodError::ResponseTooLarge { max_size: 4 }
        ));
        assert!(!cache.path().join("abcd").join("debuginfo").exists());
    }

    #[tokio::test]
    async fn request_timeout_returns_not_found_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            let body = b"debug-data";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(body).await;
        });

        let cache = TempDir::new().unwrap();
        let config = DebuginfodConfig::new([format!("http://{addr}")], cache.path())
            .unwrap()
            .with_timeout(Duration::from_millis(50));
        let client = DebuginfodClient::new(config).unwrap();

        let result = client.fetch_debuginfo(&[0xab, 0xcd]).await.unwrap();
        assert!(result.is_none());
        assert!(!cache.path().join("abcd").join("debuginfo").exists());
    }
}
