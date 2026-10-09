// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unix socket IPC server - core server logic
//!
//! This module contains the main `UnixSocketIpcServer` struct and its core
//! functionality, including:
//! - Server lifecycle management (start/stop)
//! - Atomic readiness tracking
//! - Connection acceptance and protocol routing
//!
//! The server supports JSON-RPC 2.0 (primary) and HTTP (legacy) with
//! automatic detection and routing to appropriate handlers.
//! tarpc binary RPC is served on a sibling `.tarpc.sock` when the
//! `tarpc-rpc` feature is enabled (G64 Cephalization).

use super::{
    handlers::HandlerRegistry,
    types::{JsonRpcRequest, JsonRpcResponse, Protocol},
};
use crate::btsp_handshake::{self, BtspSecurityMode};
use crate::btsp_provider::BeardogBtspProvider;
use crate::method_gate::{CallerContext, MethodGate};
use crate::platform::{
    PlatformListener, PlatformSocket, PlatformStream, PrefixedStream, Socket, SocketEndpoint,
};
use anyhow::{Context, Result};
use beardog_config::env_keys::resolve_primal_name;
use beardog_core::socket_config::{
    IpcCapabilitySymlinksConfig, install_ipc_symlinks_at, remove_ipc_symlinks_at,
};
use beardog_ipc::protocol::JSONRPC_VERSION;
use beardog_types::constants::domains::timeouts::NETWORK_READ_TIMEOUT;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

/// Per-read timeout for NDJSON connections.
///
/// Prevents indefinite blocking when a client connects but never sends a
/// newline (e.g. raw `nc` probes, `curl` health checks). On timeout the
/// connection is closed and the task freed.
pub(super) const IPC_READ_TIMEOUT: Duration = NETWORK_READ_TIMEOUT;

/// Timeout for the initial protocol-detection byte peek (BTSP vs JSON-RPC).
/// Short because clients must send the first byte quickly to identify protocol.
pub(super) const PROTOCOL_PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// Default max concurrent UDS connections (overridable via `BEARDOG_UDS_MAX_CONNECTIONS`).
const DEFAULT_UDS_MAX_CONNECTIONS: usize = 512;

/// Unix socket IPC server for inter-primal communication
pub struct UnixSocketIpcServer {
    /// Path to the Unix socket
    pub(super) socket_path: PathBuf,

    /// wateringHole v3.1 capability-domain symlinks beside [`Self::socket_path`].
    pub(super) ipc_symlinks: IpcCapabilitySymlinksConfig,

    /// BTSP provider (provides all capabilities)
    pub(super) btsp_provider: Arc<BeardogBtspProvider>,

    /// Modular handler registry for JSON-RPC methods
    pub(super) handler_registry: Arc<HandlerRegistry>,

    /// BTSP security mode (resolved at startup, checked per connection).
    pub(super) security_mode: BtspSecurityMode,

    /// Pre-dispatch authorization gate (JH-0 ecosystem standard).
    pub(super) method_gate: MethodGate,

    /// Server running state (using `RwLock` for compatibility)
    is_running: Arc<tokio::sync::RwLock<bool>>,

    /// Atomic readiness flag for lock-free checks
    is_ready: Arc<std::sync::atomic::AtomicBool>,

    /// Bounds concurrent connections to prevent resource exhaustion (Wave 150x).
    connection_semaphore: Arc<tokio::sync::Semaphore>,

    /// When true, all UDS connections must complete a BTSP handshake —
    /// the first-byte `{` bypass is disabled (defense-in-depth, Wave 151a).
    pub(super) require_btsp: bool,
}

impl UnixSocketIpcServer {
    /// Create a new Unix socket IPC server
    ///
    /// # Arguments
    /// * `socket_path` - Path to the Unix socket file
    /// * `btsp_provider` - BTSP provider for handling requests
    /// * `identity` - Primal identity (family and node)
    /// * `security_mode` - BTSP security posture (production vs development)
    /// * `ipc_symlinks` - Capability-domain symlink config (wateringHole v3.1)
    ///
    /// # Errors
    /// Returns error if unable to remove existing socket file
    pub async fn new(
        socket_path: impl AsRef<Path>,
        btsp_provider: Arc<BeardogBtspProvider>,
        identity: Arc<beardog_types::primal_identity::PrimalIdentity>,
        security_mode: BtspSecurityMode,
        ipc_symlinks: IpcCapabilitySymlinksConfig,
    ) -> Result<Self> {
        let socket_path = socket_path.as_ref().to_path_buf();

        // Remove existing socket file if present (ASYNC - non-blocking!)
        if socket_path.exists() {
            info!(path = %socket_path.display(), "Removing existing socket");
            tokio::fs::remove_file(&socket_path)
                .await
                .context("Failed to remove existing socket")?;
        }

        if security_mode.is_production() {
            info!("BTSP handshake enforcement ENABLED (production mode)");
        } else {
            info!("BTSP handshake enforcement disabled (development mode)");
        }

        let primal_name = resolve_primal_name();
        let method_gate = MethodGate::from_env(&primal_name, identity.node_id());
        info!(
            mode = method_gate.mode().as_str(),
            "Method gate initialized (JH-0/JH-1)"
        );

        let max_conn = std::env::var(beardog_config::env_keys::ENV_UDS_MAX_CONNECTIONS)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_UDS_MAX_CONNECTIONS);

        info!(max_connections = max_conn, "UDS connection cap configured");

        let require_btsp =
            beardog_errors::process_env::var(beardog_config::env_keys::ENV_UDS_REQUIRE_BTSP)
                .is_ok_and(|v| v == "1");

        if require_btsp {
            info!("UDS BTSP enforcement: STRICT — first-byte bypass disabled (defense-in-depth)");
        }

        Ok(Self {
            socket_path,
            ipc_symlinks,
            btsp_provider,
            handler_registry: HandlerRegistry::new(identity),
            security_mode,
            method_gate,
            is_running: Arc::new(tokio::sync::RwLock::new(false)),
            is_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            connection_semaphore: Arc::new(tokio::sync::Semaphore::new(max_conn)),
            require_btsp,
        })
    }

    /// Get the socket path
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Handler registry backing JSON-RPC dispatch (shared with TCP IPC).
    #[must_use]
    pub fn handler_registry(&self) -> Arc<HandlerRegistry> {
        self.handler_registry.clone()
    }

    /// Get a clone of the readiness flag
    ///
    /// This allows checking readiness even after the server has been moved
    /// into a spawn task. This is lock-free and safe for concurrent access!
    #[must_use]
    pub fn readiness_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.is_ready)
    }

    /// Check if the server is ready to accept connections
    ///
    /// This is an atomic, lock-free operation that can be safely called
    /// from any thread without blocking. Modern concurrent Rust at its best!
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.is_ready.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Wait for the server to be ready
    ///
    /// This is a non-blocking async wait that checks readiness without
    /// filesystem polling. Use this instead of `sleep` loops!
    ///
    /// Returns `true` if ready within timeout, `false` if timeout expired.
    pub async fn wait_ready(&self, timeout: std::time::Duration) -> bool {
        let start = std::time::Instant::now();
        while !self.is_ready() {
            if start.elapsed() > timeout {
                return false;
            }
            tokio::task::yield_now().await;
        }
        true
    }

    /// Wait for readiness using a readiness flag
    ///
    /// This is a standalone function for use after the server has been moved.
    /// Fully concurrent - no locks, just atomic operations!
    pub async fn wait_ready_flag(
        flag: &Arc<std::sync::atomic::AtomicBool>,
        timeout: std::time::Duration,
    ) -> bool {
        let start = std::time::Instant::now();
        while !flag.load(std::sync::atomic::Ordering::Acquire) {
            if start.elapsed() > timeout {
                return false;
            }
            tokio::task::yield_now().await;
        }
        true
    }

    /// Stop the IPC server gracefully
    ///
    /// Cleans up the socket file. The actual server loop will continue
    /// until the task is cancelled by the orchestrator.
    ///
    /// # Errors
    /// Returns error if unable to remove socket file
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Unix socket IPC server");

        // Mark as not ready (atomic, lock-free!)
        self.is_ready
            .store(false, std::sync::atomic::Ordering::Release);

        // Mark as not running (needs lock for compatibility)
        {
            let mut running = self.is_running.write().await;
            *running = false;
        }

        #[cfg(unix)]
        {
            remove_ipc_symlinks_at(
                &self.socket_path,
                &self.ipc_symlinks.symlink_suffix,
                &self.ipc_symlinks.domain_stems,
            );
        }

        if self.socket_path.exists() {
            tokio::fs::remove_file(&self.socket_path)
                .await
                .context("Failed to remove socket file")?;
            info!(path = %self.socket_path.display(), "Removed socket");
        }

        Ok(())
    }

    /// Start the Unix socket IPC server
    ///
    /// This method runs the main server loop, accepting connections and
    /// spawning handlers for each. Returns only on error or when stopped.
    ///
    /// # Errors
    /// Returns error if unable to bind to socket or accept connections
    pub async fn start(self: Arc<Self>) -> Result<()> {
        {
            let mut is_running = self.is_running.write().await;
            if *is_running {
                warn!("Unix socket IPC server already running");
                return Ok(());
            }
            *is_running = true;
        }

        info!(
            path = %self.socket_path.display(),
            "Starting Unix socket IPC server"
        );

        // Platform-agnostic socket binding (ecoBin v2.0)
        // Use socket_path provided in constructor
        let platform_type = if cfg!(target_os = "android") {
            "Android (abstract socket)"
        } else {
            "Unix (filesystem)"
        };
        info!(platform = platform_type, "IPC server platform");

        // Create endpoint from stored socket_path
        let endpoint = SocketEndpoint::Filesystem(self.socket_path.clone());

        // Bind with platform-specific logic (universal listener!)
        let mut listener = Socket::bind(&endpoint).context(format!(
            "Failed to bind socket on {}: {}",
            platform_type,
            self.socket_path.display()
        ))?;

        #[cfg(unix)]
        {
            if let Some(name) = self.socket_path.file_name() {
                let _created = install_ipc_symlinks_at(
                    &self.socket_path,
                    name,
                    &self.ipc_symlinks.symlink_suffix,
                    &self.ipc_symlinks.domain_stems,
                );
            } else {
                warn!(
                    path = %self.socket_path.display(),
                    "socket path has no filename; skipping wateringHole capability symlinks"
                );
            }
        }

        // Mark server as ready atomically (no locks needed!)
        // This enables lock-free concurrent readiness checks!
        self.is_ready
            .store(true, std::sync::atomic::Ordering::Release);

        info!(
            endpoint = %endpoint.display(),
            "Unix socket IPC server listening"
        );
        info!(
            status = "ready",
            "Unix socket IPC server status (atomic flag set)"
        );

        // Accept connections with semaphore-based backpressure + explicit
        // saturation signaling (Wave 150x).
        //
        // The semaphore bounds concurrent connections to `BEARDOG_UDS_MAX_CONNECTIONS`
        // (default 512). When at capacity, the connection gets a brief grace period
        // (100ms) for a slot to free; if none does, a JSON-RPC error is sent before
        // closing so callers can retry with backoff instead of hanging indefinitely.
        loop {
            match listener.accept().await {
                Ok(stream) => {
                    let server = Arc::clone(&self);
                    let sem = Arc::clone(&self.connection_semaphore);
                    tokio::spawn(async move {
                        let permit = match tokio::time::timeout(
                            Duration::from_millis(100),
                            sem.acquire_owned(),
                        )
                        .await
                        {
                            Ok(Ok(permit)) => permit,
                            Ok(Err(_closed)) => {
                                warn!("UDS connection rejected: semaphore closed");
                                return;
                            }
                            Err(_timeout) => {
                                warn!("UDS connection rejected: server saturated");
                                send_saturation_error(stream).await;
                                return;
                            }
                        };
                        if let Err(e) = server.handle_connection(stream).await {
                            error!(error = %e, "Connection handler error");
                        }
                        drop(permit);
                    });
                }
                Err(e) => {
                    error!(error = %e, "Failed to accept connection");
                }
            }
        }
    }
}

/// Send a JSON-RPC error to a connection when the server is at capacity.
///
/// Writes a single NDJSON line with error code `-32003` ("server saturated")
/// including `retry_after_ms` and `max_connections` hints, then closes.
/// This gives callers explicit feedback for retry-with-backoff instead of
/// an indefinite hang.
async fn send_saturation_error(mut stream: Box<dyn PlatformStream>) {
    let max_conn =
        beardog_errors::process_env::var(beardog_config::env_keys::ENV_UDS_MAX_CONNECTIONS)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_UDS_MAX_CONNECTIONS);

    let error_response = serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": -32003,
            "message": "Server saturated",
            "data": {
                "reason": "All connection slots are in use. Retry after a brief backoff.",
                "retry_after_ms": 500,
                "max_connections": max_conn,
            }
        },
        "id": serde_json::Value::Null,
    });

    if let Ok(msg) = serde_json::to_string(&error_response) {
        let _ = stream.write_all(format!("{msg}\n").as_bytes()).await;
    }
}

impl UnixSocketIpcServer {
    /// Handle a single client connection with protocol auto-detection.
    ///
    /// In production mode (`FAMILY_ID` set), peeks the first byte to distinguish
    /// JSON-RPC (`0x7B` = `{`) from BTSP binary framing — matching the TCP
    /// server pattern.
    ///
    /// When `BEARDOG_UDS_REQUIRE_BTSP=1` (defense-in-depth), the `{` bypass
    /// is restricted: plain JSON-RPC is rejected, only BTSP JSON-line
    /// `ClientHello` (`{"protocol":"btsp",...}`) is accepted. The health
    /// socket (`beardog-health.sock`) is unaffected.
    ///
    /// In development mode, falls through to the existing NDJSON path.
    ///
    /// # Errors
    /// Returns error if unable to read from stream or handle request
    async fn handle_connection(&self, stream: Box<dyn PlatformStream>) -> Result<()> {
        debug!("New IPC connection (universal platform)");

        #[cfg(unix)]
        {
            // Protocol auto-detection in production; passthrough in dev.
            let stream = if let BtspSecurityMode::Production { ref family_seed } =
                self.security_mode
            {
                let mut stream = stream;

                // Peek first byte: JSON-RPC starts with '{' (0x7B); BTSP frames
                // use a 4-byte big-endian length prefix. PrefixedStream puts the
                // consumed byte back for whichever handler wins.
                let mut peek = [0u8; 1];
                match tokio::time::timeout(PROTOCOL_PEEK_TIMEOUT, stream.read_exact(&mut peek))
                    .await
                {
                    Ok(Ok(1)) if peek[0] == b'{' && !self.require_btsp => {
                        crate::ribocipher::record_unsignalled();
                        debug!(
                            "UDS peek: JSON-RPC detected (0x7B) — bypassing BTSP for local composition"
                        );
                        Box::new(PrefixedStream::new(peek[0], stream)) as Box<dyn PlatformStream>
                    }
                    Ok(Ok(1)) if peek[0] == b'{' && self.require_btsp => {
                        crate::ribocipher::record_unsignalled();
                        debug!(
                            "UDS peek: JSON-RPC detected (0x7B) — BTSP required, routing to JSON-line handshake"
                        );
                        Box::new(PrefixedStream::new(peek[0], stream)) as Box<dyn PlatformStream>
                    }
                    Ok(Ok(1)) if crate::ribocipher::is_signal_byte(peek[0]) => {
                        crate::ribocipher::record_signalled();
                        debug!(
                            signal = format!("0x{:02X}", peek[0]),
                            "UDS peek: riboCipher signal detected"
                        );
                        return self
                            .handle_ribocipher_signal(stream, peek[0], family_seed)
                            .await;
                    }
                    Ok(Ok(_)) => {
                        debug!("BTSP production: initiating UDS handshake");
                        let mut prefixed = PrefixedStream::new(peek[0], stream);
                        // Bind BirdSong lineage into session keys even for
                        // direct BTSP connections (no riboCipher prefix).
                        let binding = self.enrich_binding_with_lineage(
                            btsp_handshake::TransportBinding::NONE,
                            family_seed,
                        );
                        match btsp_handshake::perform_server_handshake_bound(
                            &mut prefixed,
                            family_seed,
                            &binding,
                        )
                        .await
                        {
                            Ok(session) => {
                                info!(
                                    session_id = %session.session_id,
                                    cipher = %session.cipher.wire_name(),
                                    "BTSP handshake succeeded (lineage-bound)"
                                );
                                return self.handle_jsonrpc_btsp(Box::new(prefixed), session).await;
                            }
                            Err(e) => {
                                warn!(error = %e, "BTSP handshake failed — refusing connection");
                                let rejection = serde_json::json!({
                                    "jsonrpc": JSONRPC_VERSION,
                                    "error": {
                                        "code": -32600,
                                        "message": "BTSP handshake required",
                                        "data": {
                                            "reason": "This socket is family-scoped and requires a BTSP handshake before JSON-RPC traffic. Use btsp.server.create_session to initiate, or connect to the health socket (beardog-health.sock) for plaintext health probes.",
                                            "btsp_version": "2.0",
                                        }
                                    },
                                    "id": serde_json::Value::Null,
                                });
                                if let Ok(msg) = serde_json::to_string(&rejection) {
                                    let mut s: Box<dyn PlatformStream> = Box::new(prefixed);
                                    let _ = s.write_all(format!("{msg}\n").as_bytes()).await;
                                    let _ = s.flush().await;
                                }
                                return Ok(());
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "UDS peek read failed — closing connection");
                        return Ok(());
                    }
                    Err(_) => {
                        warn!("UDS peek timed out — closing connection");
                        return Ok(());
                    }
                }
            } else {
                stream
            };

            // ── NDJSON handler (dev mode or JSON-RPC auto-detected in prod) ──

            let mut buf_stream = BufReader::new(stream);
            let mut buffer = Vec::with_capacity(1024);

            let read_result =
                tokio::time::timeout(IPC_READ_TIMEOUT, buf_stream.read_until(b'\n', &mut buffer))
                    .await;

            match read_result {
                Err(_elapsed) => {
                    warn!(
                        timeout_secs = IPC_READ_TIMEOUT.as_secs(),
                        "IPC initial read timed out — closing idle connection"
                    );
                    return Ok(());
                }
                Ok(Ok(0)) => {
                    debug!("Client disconnected immediately");
                    return Ok(());
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    error!(error = %e, "Failed to read from stream");
                    return Err(anyhow::anyhow!("Failed to read: {e}"));
                }
            }

            // `from_utf8_lossy` returns `Cow`; avoid `.to_string()` so valid UTF-8
            // borrows `buffer` instead of allocating a second copy on the hot path.
            let first_line = String::from_utf8_lossy(&buffer);
            let stream = buf_stream.into_inner();

            if first_line.trim().is_empty() {
                debug!("Empty request, ignoring");
                return Ok(());
            }

            // ── BTSP JSON-line auto-detect ─────────────────────────────
            //
            // primalSpring (and other springs) send a BTSP ClientHello as
            // the first JSON line on UDS:
            //
            //   {"protocol":"btsp","version":1,"client_ephemeral_pub":"<b64>"}
            //
            // The first-byte peek sees `{` and classifies it as JSON-RPC.
            // Detect BTSP by checking for `"protocol":"btsp"` with no
            // `"jsonrpc"` field, then route to the JSON-line handshake.
            if let BtspSecurityMode::Production { ref family_seed } = self.security_mode
                && let Ok(obj) = serde_json::from_str::<serde_json::Value>(first_line.trim())
                && obj.get("protocol").and_then(|v| v.as_str()) == Some("btsp")
                && obj.get("jsonrpc").is_none()
            {
                debug!("UDS: BTSP ClientHello detected (JSON-line framed)");
                let client_hello: btsp_handshake::ClientHello = serde_json::from_value(obj)
                    .map_err(|e| anyhow::anyhow!("BTSP ClientHello parse: {e}"))?;
                return self
                    .handle_btsp_jsonline_connection(stream, &client_hello, family_seed)
                    .await;
            }

            // Defense-in-depth: when BTSP is required on local UDS, reject
            // plain JSON-RPC that did not arrive via a BTSP handshake. The
            // BTSP JSON-line ClientHello path above is the only allowed `{`
            // entry point. This prevents co-resident processes from silently
            // bypassing transport security.
            if self.require_btsp
                && matches!(self.security_mode, BtspSecurityMode::Production { .. })
            {
                warn!("UDS BTSP enforcement: rejecting plaintext — BTSP handshake required");
                let rejection = serde_json::json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "error": {
                        "code": -32600,
                        "message": "BTSP handshake required (defense-in-depth)",
                        "data": {
                            "reason": "BEARDOG_UDS_REQUIRE_BTSP=1 — all connections must complete a BTSP handshake. Send a JSON-line ClientHello ({\"protocol\":\"btsp\",\"version\":1,...}) or connect to beardog-health.sock for plaintext health checks.",
                            "btsp_version": "2.0",
                        }
                    },
                    "id": serde_json::Value::Null,
                });
                if let Ok(msg) = serde_json::to_string(&rejection) {
                    let mut s = stream;
                    let _ = s.write_all(format!("{msg}\n").as_bytes()).await;
                }
                return Ok(());
            }

            let protocol = Protocol::detect_from_bytes(first_line.as_bytes());

            match protocol {
                Protocol::Negotiation => {
                    info!(
                        security_level = protocol.security_level(),
                        protocol = "negotiation",
                        "G65 protocol negotiation greeting"
                    );
                    return self
                        .handle_protocol_negotiation(first_line.as_ref(), stream)
                        .await;
                }
                Protocol::JsonRpc => {
                    info!(
                        security_level = protocol.security_level(),
                        protocol = "json_rpc",
                        "JSON-RPC connection (primary protocol)"
                    );
                }
                Protocol::Http => {
                    warn!(
                        security_level = protocol.security_level(),
                        protocol = "http",
                        "HTTP connection (lower security than JSON-RPC for inter-primal communication)"
                    );
                    warn!("Consider migrating to JSON-RPC 2.0 over Unix sockets");
                }
            }

            match protocol {
                Protocol::JsonRpc => {
                    self.handle_jsonrpc_universal(first_line.as_ref(), stream)
                        .await?;
                }
                Protocol::Http => {
                    self.handle_http_universal(first_line.as_ref(), stream)
                        .await?;
                }
                Protocol::Negotiation => unreachable!("handled above"),
            }
        }

        #[cfg(not(unix))]
        {
            warn!("Non-Unix platform handler not yet fully implemented");
            return Err(anyhow::anyhow!(
                "Platform not yet supported in this handler"
            ));
        }

        Ok(())
    }

    /// Handle JSON-RPC request (public for testing).
    ///
    /// Uses a default `CallerContext::from_unix()` for backward compatibility
    /// with tests that don't supply caller context.
    ///
    /// # Errors
    /// Returns error if unable to parse or handle the request
    pub async fn handle_jsonrpc_request(&self, request_str: &str) -> Result<JsonRpcResponse> {
        let request: JsonRpcRequest =
            serde_json::from_str(request_str).context("Failed to parse JSON-RPC request")?;
        let mut caller = CallerContext::from_unix();
        self.route_jsonrpc(&request, &mut caller)
            .await
            .ok_or_else(|| anyhow::anyhow!("notification — no response expected"))
    }
}

impl Drop for UnixSocketIpcServer {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            remove_ipc_symlinks_at(
                &self.socket_path,
                &self.ipc_symlinks.symlink_suffix,
                &self.ipc_symlinks.domain_stems,
            );
            if self.socket_path.exists() {
                let _ = std::fs::remove_file(&self.socket_path);
            }
        }
        #[cfg(not(unix))]
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
