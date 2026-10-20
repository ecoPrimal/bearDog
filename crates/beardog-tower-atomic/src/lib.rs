// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, reason = "expect/unwrap acceptable for invariant failures in tests and bootstrap code"))]

//! # `BearDog` Tower Atomic
//!
//! **Tower Atomic** = IPC-based JSON-RPC for inter-primal communication
//!
//! ## Purpose
//!
//! `BearDog` is a **Pure Rust crypto primal** with ZERO network dependencies.
//! When `BearDog` needs HTTP/TLS, it delegates to the network transport primal via Tower Atomic.
//!
//! ## Philosophy
//!
//! - **`BearDog`**: Crypto only (ed25519, x25519, chacha20, blake3)
//! - **Network transport primal**: TLS/HTTP gateway (discovered at runtime)
//! - **Tower Atomic**: Inter-primal glue (IPC sockets, JSON-RPC)
//!
//! ## Platform Support
//!
//! - **Unix/macOS/Android**: Unix domain sockets (default)
//! - **Windows**: TCP loopback (`127.0.0.1`) via `TransportEndpoint::Tcp`
//!
//! ## Example
//!
//! ```rust,no_run
//! use beardog_tower_atomic::Client;
//! use beardog_config::env_keys;
//! use serde_json::json;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Peer is chosen by operator (env / capability discovery), not by hardcoded primal name.
//!     let peer_socket_name = std::env::var(env_keys::ENV_TOWER_ATOMIC_PEER).unwrap_or_default();
//!     let mut peer = Client::connect(&peer_socket_name).await?;
//!
//!     let response = peer.call("http.get", json!({
//!         "url": "https://api.example.com/data",
//!         "headers": { "Authorization": "Bearer ..." }
//!     })).await?;
//!
//!     println!("Status: {}", response["status"]);
//!     println!("Body: {}", response["body"]);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐                          ┌─────────────┐
//! │  This primal │   IPC Socket JSON-RPC   │ HTTP peer   │
//! │   (Crypto)   │ ───────────────────────> │ (discovered)│
//! └─────────────┘                          └─────────────┘
//!       ↓                                         ↓
//!   Ed25519, X25519                        HTTPS to external
//!   ChaCha20, Blake3                       APIs, AI providers
//! ```

use serde_json::{Value, json};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{self, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tracing::{debug, info, warn};

#[cfg(unix)]
use std::path::Path;

mod error;
pub use error::{Error, Result};

#[cfg(unix)]
mod discovery;
#[cfg(unix)]
use discovery::discover_primal_socket;

/// Platform-agnostic IPC stream: UDS on Unix, TCP on all platforms.
enum IpcStream {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    Tcp(tokio::net::TcpStream),
}

impl AsyncRead for IpcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for IpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_flush(cx),
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Tower Atomic client for inter-primal communication
///
/// Uses platform-native IPC (Unix domain sockets on Unix, TCP loopback on
/// Windows) and JSON-RPC 2.0 for fast, secure inter-primal communication.
pub struct Client {
    stream: IpcStream,
    /// Target primal name
    primal_name: String,
    /// Request ID counter
    request_id: u64,
}

impl Client {
    /// Connect to a primal via platform-native IPC.
    ///
    /// On Unix, discovers the primal's socket path via the 5-tier standard.
    /// On Windows, callers should use [`Self::connect_endpoint`] with a
    /// `TransportEndpoint::Tcp` endpoint instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PrimalNotFound`] if the primal's socket cannot be located, or
    /// [`Error::ConnectionFailed`] if the connection fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use beardog_tower_atomic::Client;
    /// use beardog_config::env_keys;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let peer = Client::connect(&std::env::var(env_keys::ENV_TOWER_ATOMIC_PEER).unwrap_or_default()).await?;
    ///     Ok(())
    /// }
    /// ```
    #[cfg(unix)]
    pub async fn connect(primal_name: &str) -> Result<Self> {
        info!("Connecting via Tower Atomic (socket key: {})", primal_name);

        let socket_path = discover_primal_socket(primal_name).await?;
        debug!("Found socket at: {:?}", socket_path);

        Self::connect_unix_path(&socket_path, primal_name).await
    }

    /// Connect to an existing Unix socket path (capability / env resolved).
    ///
    /// `peer_label` is used only for logging (e.g. socket path or discovery id).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if the Unix socket cannot be opened.
    #[cfg(unix)]
    pub async fn connect_unix_path(socket_path: &Path, peer_label: &str) -> Result<Self> {
        let stream = tokio::net::UnixStream::connect(socket_path)
            .await
            .map_err(|e| {
                Error::ConnectionFailed(format!(
                    "Failed to connect Tower Atomic peer `{peer_label}` at {}: {e}",
                    socket_path.display()
                ))
            })?;

        Self::finish_connect(IpcStream::Unix(stream), peer_label).await
    }

    /// Connect to a TCP endpoint (cross-platform, used on Windows or when
    /// `TransportEndpoint::Tcp` is resolved).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if the TCP connection fails.
    pub async fn connect_tcp(host: &str, port: u16, peer_label: &str) -> Result<Self> {
        let stream = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|e| {
                Error::ConnectionFailed(format!(
                    "Failed to connect Tower Atomic peer `{peer_label}` at {host}:{port}: {e}"
                ))
            })?;

        Self::finish_connect(IpcStream::Tcp(stream), peer_label).await
    }

    /// Send the `riboCipher` protocol signal and finalize the `Client`.
    async fn finish_connect(mut stream: IpcStream, peer_label: &str) -> Result<Self> {
        use beardog_types::constants::domains::network::ribocipher;

        stream
            .write_all(&ribocipher::clear_signal(ribocipher::PROTO_NDJSON_JSONRPC))
            .await
            .map_err(|e| {
                Error::ConnectionFailed(format!("Failed to send riboCipher signal: {e}"))
            })?;

        info!("Tower Atomic connected ({peer_label})");

        Ok(Self {
            stream,
            primal_name: peer_label.to_string(),
            request_id: 0,
        })
    }

    /// Connect via a structured [`TransportEndpoint`].
    ///
    /// UDS endpoints connect on Unix; TCP endpoints connect on all platforms.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if the endpoint type is unsupported
    /// on the current platform or the connection fails.
    pub async fn connect_endpoint(
        endpoint: &beardog_types::btsp::TransportEndpoint,
        peer_label: &str,
    ) -> Result<Self> {
        match endpoint {
            #[cfg(unix)]
            beardog_types::btsp::TransportEndpoint::Uds { path } => {
                Self::connect_unix_path(path, peer_label).await
            }
            beardog_types::btsp::TransportEndpoint::Tcp { host, port } => {
                Self::connect_tcp(host, *port, peer_label).await
            }
            other => Err(Error::ConnectionFailed(format!(
                "Unsupported transport for Tower Atomic on this platform: {other}"
            ))),
        }
    }

    /// Call a method via JSON-RPC 2.0
    ///
    /// # Arguments
    ///
    /// * `method` - Method name (e.g., "http.get", "crypto.sign")
    /// * `params` - Method parameters as JSON value
    ///
    /// # Returns
    ///
    /// The JSON-RPC `result` field on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SerializationFailed`] if the request or response JSON cannot be encoded or
    /// decoded, [`Error::ConnectionFailed`] if the socket read or write fails, or
    /// [`Error::JsonRpcError`] if the peer reports a JSON-RPC error or the response omits both
    /// `result` and a well-formed error object.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use beardog_tower_atomic::Client;
    /// use beardog_config::env_keys;
    /// use serde_json::json;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut peer = Client::connect(&std::env::var(env_keys::ENV_TOWER_ATOMIC_PEER).unwrap_or_default()).await?;
    ///
    ///     let response = peer.call("http.get", json!({
    ///         "url": "https://api.example.com"
    ///     })).await?;
    ///
    ///     println!("Response: {:?}", response);
    ///     Ok(())
    /// }
    /// ```
    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        // Increment request ID
        self.request_id += 1;
        let id = self.request_id;

        debug!("📤 Tower Atomic JSON-RPC `{}` (id={})", method, id);

        // Build JSON-RPC 2.0 request
        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id
        });

        // Serialize request
        let request_str = serde_json::to_string(&request)
            .map_err(|e| Error::SerializationFailed(format!("Failed to serialize request: {e}")))?;

        // Send request (newline-delimited JSON)
        self.stream
            .write_all(request_str.as_bytes())
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Failed to write request: {e}")))?;
        self.stream
            .write_all(b"\n")
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Failed to write newline: {e}")))?;

        debug!("📤 Sent: {}", request_str);

        // Read response (newline-delimited JSON)
        let mut reader = BufReader::new(&mut self.stream);
        let mut response_str = String::new();
        reader
            .read_line(&mut response_str)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Failed to read response: {e}")))?;

        debug!("📥 Received: {}", response_str.trim());

        // Parse response
        let response: JsonRpcResponse = serde_json::from_str(&response_str)
            .map_err(|e| Error::SerializationFailed(format!("Failed to parse response: {e}")))?;

        // Check for JSON-RPC error
        if let Some(error) = response.error {
            warn!(
                "⚠️  JSON-RPC error from {}: {} (code {})",
                self.primal_name, error.message, error.code
            );
            return Err(Error::JsonRpcError {
                code: error.code,
                message: error.message,
                data: error.data,
            });
        }

        // Return result
        match response.result {
            Some(result) => {
                debug!("✅ Call successful (id={})", id);
                Ok(result)
            }
            None => Err(Error::JsonRpcError {
                code: -32603,
                message: "No result or error in JSON-RPC response".to_string(),
                data: None,
            }),
        }
    }

    /// Get the connected primal name
    pub fn primal_name(&self) -> &str {
        &self.primal_name
    }
}

// JSON-RPC 2.0 types — canonical definitions from cellmembrane-types.
// JsonRpcError is resolved transitively via JsonRpcResponse::error field.
use cellmembrane_types::ecosystem::JsonRpcResponse;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::sync::Notify;

    #[cfg(unix)]
    #[tokio::test]
    async fn test_connect_to_mock_primal_uds() {
        use tempfile::tempdir;
        use tokio::net::UnixListener;

        let dir = tempdir().expect("tempdir for mock primal socket");
        let socket_path = dir.path().join("mock_primal.sock");

        let listener = UnixListener::bind(&socket_path).expect("bind mock primal unix listener");
        let server_socket_path = socket_path.clone();

        let ready = Arc::new(Notify::new());
        tokio::spawn({
            let ready_tx = Arc::clone(&ready);
            async move {
                ready_tx.notify_one();
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("mock server accepts connection");

                let mut reader = BufReader::new(&mut stream);
                let mut request = String::new();
                reader
                    .read_line(&mut request)
                    .await
                    .expect("mock server reads JSON-RPC line");

                let response = json!({
                    "jsonrpc": "2.0",
                    "result": { "status": "ok" },
                    "id": 1
                });
                stream
                    .write_all(
                        serde_json::to_string(&response)
                            .expect("JSON-RPC response serializes")
                            .as_bytes(),
                    )
                    .await
                    .expect("mock server writes response body");
                stream
                    .write_all(b"\n")
                    .await
                    .expect("mock server writes newline");
            }
        });

        ready.notified().await;

        let stream = tokio::net::UnixStream::connect(&server_socket_path)
            .await
            .expect("client connects to mock primal");
        let mut client = Client {
            stream: IpcStream::Unix(stream),
            primal_name: "mock_primal".to_string(),
            request_id: 0,
        };

        let response = client
            .call("test.method", json!({"param": "value"}))
            .await
            .expect("JSON-RPC call to mock primal succeeds");

        assert_eq!(response["status"], "ok");
    }

    #[tokio::test]
    async fn test_connect_to_mock_primal_tcp() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TCP listener");
        let addr = listener.local_addr().expect("local_addr");

        let ready = Arc::new(Notify::new());
        tokio::spawn({
            let ready_tx = Arc::clone(&ready);
            async move {
                ready_tx.notify_one();
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("mock TCP server accepts connection");

                // `finish_connect` sends a 2-byte riboCipher prefix; consume it.
                let mut prefix = [0u8; 2];
                stream
                    .read_exact(&mut prefix)
                    .await
                    .expect("mock TCP server reads riboCipher prefix");

                let mut reader = BufReader::new(&mut stream);
                let mut request = String::new();
                reader
                    .read_line(&mut request)
                    .await
                    .expect("mock TCP server reads JSON-RPC line");

                let response = json!({
                    "jsonrpc": "2.0",
                    "result": { "data": 42 },
                    "id": 1
                });
                stream
                    .write_all(
                        serde_json::to_string(&response)
                            .expect("JSON-RPC response serializes")
                            .as_bytes(),
                    )
                    .await
                    .expect("mock TCP server writes response body");
                stream
                    .write_all(b"\n")
                    .await
                    .expect("mock TCP server writes newline");
            }
        });

        ready.notified().await;

        let mut client = Client::connect_tcp("127.0.0.1", addr.port(), "mock_tcp")
            .await
            .expect("TCP connect succeeds");

        let response = client
            .call("test.method", json!({"param": "value"}))
            .await
            .expect("JSON-RPC call via TCP succeeds");

        assert_eq!(response["data"], 42);
    }
}
