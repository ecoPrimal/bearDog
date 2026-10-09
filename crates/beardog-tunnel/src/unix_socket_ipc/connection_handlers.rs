// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection protocol handlers for the Unix socket IPC server.
//!
//! Handles JSON-RPC (NDJSON), HTTP, and BTSP (both length-prefixed and
//! JSON-line framed) connections after protocol detection in [`super::server`].
//!
//! After a successful `btsp.negotiate` response (Phase 3), the connection
//! transparently transitions from NDJSON to encrypted frame I/O.

use super::server::{IPC_READ_TIMEOUT, UnixSocketIpcServer};
use crate::btsp_handshake::{self, BtspSession, Phase3Session};
use crate::method_gate::CallerContext;
use crate::platform::PlatformStream;
use crate::ribocipher;
use anyhow::Result;
use beardog_config::env_keys;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, info, warn};

impl UnixSocketIpcServer {
    /// Route a connection that sent a riboCipher signal prefix.
    ///
    /// Called from the connection accept path when the first byte on a new Unix
    /// socket connection matches a riboCipher tier signal (e.g. `SIGNAL_CLEAR`).
    /// Reads the tier-specific payload after the signal byte, resolves the
    /// protocol type, then dispatches to the appropriate handler.
    ///
    /// Wired from `handle_connection` when the first peek byte matches a
    /// riboCipher tier signal (0xEC/0xED/0xEE).
    pub(super) async fn handle_ribocipher_signal(
        &self,
        mut stream: Box<dyn PlatformStream>,
        signal_byte: u8,
        family_seed: &btsp_handshake::FamilySeed,
    ) -> Result<()> {
        match signal_byte {
            ribocipher::SIGNAL_CLEAR => {
                let mut proto_buf = [0u8; 1];
                stream.read_exact(&mut proto_buf).await?;
                let protocol_type = proto_buf[0];

                info!(
                    protocol = ribocipher::protocol_name(protocol_type),
                    byte = format!("0x{:02X}", protocol_type),
                    "riboCipher: clear signal — routing"
                );

                self.dispatch_by_protocol(stream, protocol_type, family_seed, "clear")
                    .await
            }
            ribocipher::SIGNAL_MITO => {
                let mut tag = [0u8; 4];
                stream.read_exact(&mut tag).await?;

                if let Some(protocol_type) =
                    ribocipher::decode_mito_tag(family_seed.as_bytes(), &tag)
                {
                    info!(
                        protocol = ribocipher::protocol_name(protocol_type),
                        tag = format!("{:02X}{:02X}{:02X}{:02X}", tag[0], tag[1], tag[2], tag[3]),
                        "riboCipher: mito-beacon decoded — routing"
                    );
                    self.dispatch_by_protocol(stream, protocol_type, family_seed, "mito")
                        .await
                } else {
                    warn!(
                        tag = format!("{:02X}{:02X}{:02X}{:02X}", tag[0], tag[1], tag[2], tag[3]),
                        "riboCipher: mito-beacon tag verification failed — wrong family seed or unknown protocol"
                    );
                    Ok(())
                }
            }
            ribocipher::SIGNAL_NUCLEAR => {
                let mut payload = [0u8; 6];
                stream.read_exact(&mut payload).await?;
                info!("riboCipher: nuclear-sealed signal received (Tier 3 — future expansion)");
                warn!("riboCipher: nuclear-tier not yet implemented — closing connection");
                Ok(())
            }
            _ => unreachable!("is_signal_byte guards this branch"),
        }
    }

    /// Dispatch to the appropriate handler based on the decoded riboCipher
    /// protocol type. Shared by both clear and mito-beacon signal paths.
    async fn dispatch_by_protocol(
        &self,
        mut stream: Box<dyn PlatformStream>,
        protocol_type: u8,
        family_seed: &btsp_handshake::FamilySeed,
        tier_label: &str,
    ) -> Result<()> {
        match protocol_type {
            ribocipher::PROTO_NDJSON_JSONRPC => self.handle_jsonrpc_universal("", stream).await,
            ribocipher::PROTO_BTSP_BINARY => {
                match btsp_handshake::perform_server_handshake(&mut stream, family_seed).await {
                    Ok(session) => {
                        info!(
                            session_id = %session.session_id,
                            cipher = %session.cipher.wire_name(),
                            "{tier_label}→BTSP handshake succeeded"
                        );
                        self.handle_jsonrpc_btsp(stream, session).await
                    }
                    Err(e) => {
                        warn!(error = %e, "{tier_label}→BTSP handshake failed");
                        Ok(())
                    }
                }
            }
            ribocipher::PROTO_BTSP_JSONLINE => {
                let mut buf = Vec::with_capacity(512);
                let mut buf_reader = BufReader::new(stream);
                buf_reader.read_until(b'\n', &mut buf).await?;
                let line = String::from_utf8_lossy(&buf);
                if let Ok(hello) = serde_json::from_str::<btsp_handshake::ClientHello>(line.trim())
                {
                    let stream = buf_reader.into_inner();
                    self.handle_btsp_jsonline_connection(stream, &hello, family_seed)
                        .await
                } else {
                    warn!("{tier_label}: BTSP JSON-line signal but invalid ClientHello");
                    Ok(())
                }
            }
            ribocipher::PROTO_HTTP => self.handle_http_universal("", stream).await,
            ribocipher::PROTO_PROBE => {
                let signal_name = if tier_label == "mito" {
                    "riboCipher-mito-v1"
                } else {
                    "riboCipher-v1"
                };
                let response = serde_json::json!({
                    "status": "ok",
                    "primal": env_keys::resolve_primal_name(),
                    "signal": signal_name
                });
                let msg = serde_json::to_string(&response)?;
                stream.write_all(format!("{msg}\n").as_bytes()).await?;
                stream.flush().await?;
                Ok(())
            }
            _ => {
                warn!(
                    protocol_type = format!("0x{:02X}", protocol_type),
                    "{tier_label}: unknown protocol type"
                );
                Ok(())
            }
        }
    }

    /// Handle G65 protocol negotiation.
    ///
    /// When the first line is `PROTOCOLS: tarpc,jsonrpc\n`, this method:
    /// 1. Parses the client's protocol preferences
    /// 2. Selects the best mutual protocol (tarpc preferred, then jsonrpc)
    /// 3. Responds with `PROTOCOL: <selected>\n`
    /// 4. Routes the connection to the selected protocol handler
    ///
    /// If no mutual protocol exists, responds with an error line and closes.
    pub(super) async fn handle_protocol_negotiation(
        &self,
        greeting_line: &str,
        mut stream: Box<dyn PlatformStream>,
    ) -> Result<()> {
        let client_prefs = parse_g65_greeting(greeting_line);

        if client_prefs.is_empty() {
            warn!("G65: empty or unparseable PROTOCOLS greeting — closing");
            stream
                .write_all(b"PROTOCOL: NONE supported=tarpc,jsonrpc\n")
                .await?;
            return Ok(());
        }

        // Server preference: tarpc > jsonrpc. First client pref we also support wins.
        let selected = client_prefs
            .iter()
            .find(|p| matches!(p.as_str(), "tarpc" | "jsonrpc"))
            .map(String::as_str);

        match selected {
            Some("tarpc") => {
                info!(selected = "tarpc", "G65: protocol negotiated");
                stream.write_all(b"PROTOCOL: tarpc\n").await?;
                stream.flush().await?;

                #[cfg(all(unix, feature = "tarpc-rpc"))]
                {
                    self.serve_tarpc_on_stream(stream).await?;
                }

                #[cfg(not(all(unix, feature = "tarpc-rpc")))]
                {
                    warn!("G65: tarpc negotiated but tarpc-rpc feature not enabled");
                }

                Ok(())
            }
            Some("jsonrpc") => {
                info!(selected = "jsonrpc", "G65: protocol negotiated");
                stream.write_all(b"PROTOCOL: jsonrpc\n").await?;
                stream.flush().await?;
                self.handle_jsonrpc_universal("", stream).await
            }
            _ => {
                warn!("G65: no mutual protocol — closing");
                stream
                    .write_all(b"PROTOCOL: NONE supported=tarpc,jsonrpc\n")
                    .await?;
                Ok(())
            }
        }
    }

    /// Serve tarpc binary RPC on an already-negotiated stream (G65 Phase 3).
    ///
    /// Wraps the stream in tarpc's length-delimited bincode transport and
    /// processes requests using the same `BearDogRpcServer` as the sibling
    /// `.tarpc.sock` listener.
    #[cfg(all(unix, feature = "tarpc-rpc"))]
    async fn serve_tarpc_on_stream(&self, stream: Box<dyn PlatformStream>) -> Result<()> {
        use futures::StreamExt;
        use crate::tarpc_service::BearDogRpc;
        use tarpc::server::{BaseChannel, Channel};

        let transport = tarpc::serde_transport::Transport::from((
            stream,
            tarpc::tokio_serde::formats::Bincode::default(),
        ));

        let identity = std::sync::Arc::new(
            beardog_types::primal_identity::PrimalIdentity::from_env(),
        );
        let server = crate::tarpc_service::BearDogRpcServer::new(identity);
        let channel = BaseChannel::with_defaults(transport);

        info!("G65: serving tarpc on negotiated connection");
        channel
            .execute(server.serve())
            .for_each(|resp| async {
                tokio::spawn(resp);
            })
            .await;

        Ok(())
    }

    /// Handle JSON-RPC requests using universal platform stream.
    ///
    /// After writing a successful `btsp.negotiate` response, transitions the
    /// connection to Phase 3 encrypted frame I/O.
    pub(super) async fn handle_jsonrpc_universal(
        &self,
        first_line: &str,
        stream: Box<dyn PlatformStream>,
    ) -> Result<()> {
        let mut caller = CallerContext::from_unix_with_peer(stream.peer_credentials());
        let mut buf_stream = BufReader::new(stream);

        if let Some(response) = self
            .handle_one_jsonrpc_request_universal(first_line, &mut caller)
            .await?
        {
            buf_stream.get_mut().write_all(response.as_bytes()).await?;
            buf_stream.get_mut().write_all(b"\n").await?;

            if let Some(session) = try_phase3_upgrade(first_line, &response) {
                buf_stream.get_mut().flush().await?;
                let stream = buf_stream.into_inner();
                return self.handle_jsonrpc_phase3(stream, session).await;
            }
        }

        let mut line_buf = Vec::with_capacity(1024);

        loop {
            line_buf.clear();

            let read_result = tokio::time::timeout(
                IPC_READ_TIMEOUT,
                buf_stream.read_until(b'\n', &mut line_buf),
            )
            .await;

            match read_result {
                Err(_elapsed) => {
                    debug!(
                        timeout_secs = IPC_READ_TIMEOUT.as_secs(),
                        "IPC read timed out — closing idle connection"
                    );
                    return Ok(());
                }
                Ok(Ok(0)) => {
                    debug!("Client disconnected gracefully");
                    return Ok(());
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    error!(error = %e, "Read error");
                    return Err(anyhow::anyhow!("Read failed: {e}"));
                }
            }

            let line = String::from_utf8_lossy(&line_buf);
            if line.trim().is_empty() {
                continue;
            }

            match self
                .handle_one_jsonrpc_request_universal(&line, &mut caller)
                .await
            {
                Ok(Some(response)) => {
                    if let Err(e) = buf_stream.get_mut().write_all(response.as_bytes()).await {
                        warn!(error = %e, "Failed to write response");
                        break;
                    }
                    if let Err(e) = buf_stream.get_mut().write_all(b"\n").await {
                        warn!(error = %e, "Failed to write newline");
                        break;
                    }

                    if let Some(session) = try_phase3_upgrade(&line, &response) {
                        let _ = buf_stream.get_mut().flush().await;
                        let stream = buf_stream.into_inner();
                        return self.handle_jsonrpc_phase3(stream, session).await;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(error = %e, "Error handling request");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle HTTP requests using universal platform stream.
    pub(super) async fn handle_http_universal(
        &self,
        _first_line: &str,
        mut stream: Box<dyn PlatformStream>,
    ) -> Result<()> {
        let response = b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 50\r\n\r\nHTTP deprecated - use JSON-RPC over Unix sockets\n";
        stream.write_all(response).await?;
        Ok(())
    }

    /// Handle a UDS connection that began with a JSON-line BTSP `ClientHello`.
    ///
    /// Completes the 4-step handshake (steps 2–4) using newline-delimited JSON,
    /// then transitions to the appropriate post-handshake handler:
    /// - `Null` cipher → plain NDJSON JSON-RPC loop
    /// - Encrypted cipher → length-prefixed encrypted frame loop
    pub(super) async fn handle_btsp_jsonline_connection(
        &self,
        mut stream: Box<dyn PlatformStream>,
        client_hello: &btsp_handshake::ClientHello,
        family_seed: &btsp_handshake::FamilySeed,
    ) -> Result<()> {
        match btsp_handshake::continue_server_handshake_jsonline(
            &mut stream,
            client_hello,
            family_seed,
        )
        .await
        {
            Ok(session) => {
                info!(
                    session_id = %session.session_id,
                    cipher = %session.cipher.wire_name(),
                    "BTSP handshake succeeded (JSON-line framed)"
                );
                if session.cipher == btsp_handshake::BtspCipher::Null {
                    self.handle_jsonrpc_ndjson_loop(stream).await
                } else {
                    self.handle_jsonrpc_btsp(stream, session).await
                }
            }
            Err(e) => {
                warn!(error = %e, "BTSP handshake failed (JSON-line)");
                Ok(())
            }
        }
    }

    /// Read NDJSON JSON-RPC requests in a loop (post-handshake, null cipher).
    ///
    /// Transitions to Phase 3 encrypted frame I/O if `btsp.negotiate`
    /// succeeds with a non-null cipher.
    pub(super) async fn handle_jsonrpc_ndjson_loop(
        &self,
        stream: Box<dyn PlatformStream>,
    ) -> Result<()> {
        let mut caller = CallerContext::from_unix_with_peer(stream.peer_credentials());
        let mut buf_stream = BufReader::new(stream);
        let mut line_buf = Vec::with_capacity(1024);

        loop {
            line_buf.clear();

            let read_result = tokio::time::timeout(
                IPC_READ_TIMEOUT,
                buf_stream.read_until(b'\n', &mut line_buf),
            )
            .await;

            match read_result {
                Err(_) => {
                    debug!("Post-handshake NDJSON read timed out — closing connection");
                    return Ok(());
                }
                Ok(Ok(0)) => {
                    debug!("Client disconnected after BTSP handshake");
                    return Ok(());
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(anyhow::anyhow!("Post-handshake read: {e}")),
            }

            let line = String::from_utf8_lossy(&line_buf);
            if line.trim().is_empty() {
                continue;
            }

            if let Some(response) = self
                .handle_one_jsonrpc_request_universal(line.as_ref(), &mut caller)
                .await?
            {
                buf_stream.get_mut().write_all(response.as_bytes()).await?;
                buf_stream.get_mut().write_all(b"\n").await?;

                if let Some(session) = try_phase3_upgrade(&line, &response) {
                    let _ = buf_stream.get_mut().flush().await;
                    let stream = buf_stream.into_inner();
                    return self.handle_jsonrpc_phase3(stream, session).await;
                }
            }
        }
    }

    /// Handle JSON-RPC over BTSP encrypted frames (Phase 2 — counter nonces).
    ///
    /// Each frame is decrypted → parsed as JSON-RPC → processed → encrypted → sent.
    pub(super) async fn handle_jsonrpc_btsp(
        &self,
        mut stream: Box<dyn PlatformStream>,
        mut session: BtspSession,
    ) -> Result<()> {
        let mut caller = CallerContext::from_unix_with_peer(stream.peer_credentials());
        caller.btsp_family_verified = true;
        loop {
            let frame = match btsp_handshake::read_frame(&mut stream).await {
                Ok(f) => f,
                Err(e) => {
                    debug!(error = %e, "BTSP frame read ended");
                    return Ok(());
                }
            };

            let plaintext = match session.decrypt_frame(&frame) {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "BTSP frame decrypt failed — dropping connection");
                    return Ok(());
                }
            };

            let line = match String::from_utf8(plaintext) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "BTSP frame not valid UTF-8");
                    continue;
                }
            };

            if line.trim().is_empty() {
                continue;
            }

            if let Some(response_str) = self
                .handle_one_jsonrpc_request_universal(&line, &mut caller)
                .await?
            {
                let encrypted = session
                    .encrypt_frame(response_str.as_bytes())
                    .map_err(|e| anyhow::anyhow!("BTSP encrypt failed: {e}"))?;

                btsp_handshake::write_frame(&mut stream, &encrypted)
                    .await
                    .map_err(|e| anyhow::anyhow!("BTSP frame write failed: {e}"))?;
            }
        }
    }

    /// Handle JSON-RPC over Phase 3 encrypted frames (random nonces).
    ///
    /// Entered after a successful `btsp.negotiate` response. Each subsequent
    /// message uses length-prefixed encrypted framing:
    /// `[4B len BE u32][12B random nonce][ciphertext + Poly1305 tag]`
    pub(super) async fn handle_jsonrpc_phase3(
        &self,
        mut stream: Box<dyn PlatformStream>,
        session: Phase3Session,
    ) -> Result<()> {
        let mut caller = CallerContext::from_unix_with_peer(stream.peer_credentials());
        info!("BTSP Phase 3: encrypted frame I/O active");
        loop {
            let frame = match btsp_handshake::read_frame(&mut stream).await {
                Ok(f) => f,
                Err(e) => {
                    debug!(error = %e, "Phase 3 frame read ended");
                    return Ok(());
                }
            };

            let plaintext = match session.decrypt_frame(&frame) {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "Phase 3 frame decrypt failed — dropping connection");
                    return Ok(());
                }
            };

            let line = match String::from_utf8(plaintext) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "Phase 3 frame not valid UTF-8");
                    continue;
                }
            };

            if line.trim().is_empty() {
                continue;
            }

            if let Some(response_str) = self
                .handle_one_jsonrpc_request_universal(&line, &mut caller)
                .await?
            {
                let encrypted = session
                    .encrypt_frame(response_str.as_bytes())
                    .map_err(|e| anyhow::anyhow!("Phase 3 encrypt failed: {e}"))?;

                btsp_handshake::write_frame(&mut stream, &encrypted)
                    .await
                    .map_err(|e| anyhow::anyhow!("Phase 3 frame write failed: {e}"))?;
            }
        }
    }

    /// Route a parsed JSON-RPC request through the method gate and handler registry.
    ///
    /// Handles version validation, notification semantics (no response when `id`
    /// is absent per JSON-RPC 2.0 spec section 4.1), auth method interception
    /// (JH-0), pre-dispatch authorization, and error-code inference.
    pub(super) async fn route_jsonrpc(
        &self,
        request: &super::types::JsonRpcRequest,
        caller: &mut CallerContext,
    ) -> Option<super::types::JsonRpcResponse> {
        use crate::method_gate::{dispatch_auth_method, is_gate_handled_method};
        use beardog_ipc::protocol::JSONRPC_VERSION;
        use std::borrow::Cow;

        debug!(method = %request.method, "JSON-RPC request");

        if let Some(token) = request
            .params
            .as_ref()
            .and_then(|p| p.get("_bearer_token"))
            .and_then(serde_json::Value::as_str)
        {
            caller.bearer_token = Some(token.to_owned());
        }

        let id = request.id.clone().unwrap_or(serde_json::Value::Null);
        let is_notification = request.id.is_none();

        if request.jsonrpc != "2.0" {
            if is_notification {
                return None;
            }
            return Some(super::types::JsonRpcResponse {
                jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
                result: None,
                error: Some(super::types::JsonRpcError::invalid_request(
                    "Invalid JSON-RPC version (must be 2.0)",
                )),
                id,
            });
        }

        if is_gate_handled_method(&request.method) {
            if is_notification {
                return None;
            }
            if let Some(result) = dispatch_auth_method(
                &request.method,
                &self.method_gate,
                caller,
                request.params.as_ref(),
            ) {
                return Some(super::types::JsonRpcResponse {
                    jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
                    result: Some(result),
                    error: None,
                    id,
                });
            }
        }

        if let Err(gate_error) = self.method_gate.check(&request.method, caller) {
            if is_notification {
                return None;
            }
            return Some(super::types::JsonRpcResponse {
                jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
                result: None,
                error: Some(gate_error),
                id,
            });
        }

        let result: super::handlers::HandlerResult = self
            .handler_registry
            .route(
                &request.method,
                request.params.as_ref(),
                &self.btsp_provider,
            )
            .await;

        if is_notification {
            return None;
        }

        Some(match result {
            Ok(value) => super::types::JsonRpcResponse {
                jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
                result: Some(value),
                error: None,
                id,
            },
            Err(e) => {
                let error = super::types::JsonRpcError {
                    code: e.json_rpc_code(),
                    message: e.to_string(),
                    data: None,
                };

                super::types::JsonRpcResponse {
                    jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
                    result: None,
                    error: Some(error),
                    id,
                }
            }
        })
    }

    /// Process one JSON-RPC request line and return the serialized response, or
    /// `None` for notifications.
    pub(super) async fn handle_one_jsonrpc_request_universal(
        &self,
        line: &str,
        caller: &mut CallerContext,
    ) -> Result<Option<String>> {
        use beardog_ipc::protocol::JSONRPC_VERSION;
        use std::borrow::Cow;

        let request: super::types::JsonRpcRequest = match serde_json::from_str(line.trim()) {
            Ok(req) => req,
            Err(e) => {
                warn!(error = %e, "Invalid JSON-RPC request");
                let error_response = super::types::JsonRpcResponse {
                    jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
                    result: None,
                    error: Some(super::types::JsonRpcError::parse_error(format!(
                        "Parse error: {e}"
                    ))),
                    id: serde_json::Value::Null,
                };
                return Ok(Some(serde_json::to_string(&error_response)?));
            }
        };

        match self.route_jsonrpc(&request, caller).await {
            Some(resp) => Ok(Some(serde_json::to_string(&resp)?)),
            None => Ok(None),
        }
    }
}

/// Detect a successful Phase 3 negotiate from a request/response pair and
/// derive session keys for the encrypted frame transition.
///
/// Returns `Some(Phase3Session)` when the request was `btsp.negotiate` and the
/// server selected a non-null cipher. Returns `None` for all other methods or
/// when the null cipher was selected.
fn try_phase3_upgrade(request_line: &str, response_str: &str) -> Option<Phase3Session> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let req: serde_json::Value = serde_json::from_str(request_line.trim()).ok()?;
    if req.get("method")?.as_str()? != "btsp.negotiate" {
        return None;
    }

    let resp: serde_json::Value = serde_json::from_str(response_str.trim()).ok()?;
    let result = resp.get("result")?;
    let cipher = result.get("cipher")?.as_str()?;
    if cipher == "null" {
        return None;
    }

    let server_nonce_b64 = result.get("server_nonce")?.as_str()?;
    let client_nonce_b64 = req.get("params")?.get("client_nonce")?.as_str()?;

    let client_nonce = BASE64.decode(client_nonce_b64).ok()?;
    let server_nonce = BASE64.decode(server_nonce_b64).ok()?;

    let family_seed = beardog_errors::process_env::var(env_keys::ENV_FAMILY_SEED_PREFIXED)
        .or_else(|_| beardog_errors::process_env::var(env_keys::ENV_FAMILY_SEED))
        .ok()
        .filter(|s| s.len() >= 16)
        .map(String::into_bytes)?;

    let handshake_key = btsp_handshake::crypto::derive_handshake_key(&family_seed).ok()?;
    let keys = btsp_handshake::crypto::derive_phase3_session_keys(
        &handshake_key,
        &client_nonce,
        &server_nonce,
    )
    .ok()?;

    info!(
        cipher = cipher,
        "BTSP Phase 3: transitioning connection to encrypted frame I/O"
    );

    Some(Phase3Session::new(keys))
}

/// Parse a G65 `PROTOCOLS:` greeting line into a list of protocol names.
///
/// Accepts `PROTOCOLS: tarpc,jsonrpc\n` or `PROTOCOLS:tarpc,jsonrpc\n`.
/// Returns protocol names as lowercase strings in the client's preference order.
fn parse_g65_greeting(line: &str) -> Vec<String> {
    let trimmed = line.trim();
    let payload = if let Some(rest) = trimmed.strip_prefix("PROTOCOLS:") {
        rest.trim()
    } else if let Some(rest) = trimmed.strip_prefix("PROTOCOLS ") {
        rest.trim()
    } else {
        return Vec::new();
    };

    payload
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod g65_tests {
    use super::*;

    #[test]
    fn parse_greeting_tarpc_jsonrpc() {
        let prefs = parse_g65_greeting("PROTOCOLS: tarpc,jsonrpc\n");
        assert_eq!(prefs, vec!["tarpc", "jsonrpc"]);
    }

    #[test]
    fn parse_greeting_jsonrpc_only() {
        let prefs = parse_g65_greeting("PROTOCOLS: jsonrpc\n");
        assert_eq!(prefs, vec!["jsonrpc"]);
    }

    #[test]
    fn parse_greeting_no_space() {
        let prefs = parse_g65_greeting("PROTOCOLS:tarpc\n");
        assert_eq!(prefs, vec!["tarpc"]);
    }

    #[test]
    fn parse_greeting_with_unknown() {
        let prefs = parse_g65_greeting("PROTOCOLS: grpc,tarpc,quic,jsonrpc\n");
        assert_eq!(prefs, vec!["grpc", "tarpc", "quic", "jsonrpc"]);
    }

    #[test]
    fn parse_greeting_empty() {
        assert!(parse_g65_greeting("NOT_PROTOCOLS: tarpc\n").is_empty());
    }

    #[test]
    fn parse_greeting_space_prefix() {
        let prefs = parse_g65_greeting("PROTOCOLS tarpc,jsonrpc\n");
        assert_eq!(prefs, vec!["tarpc", "jsonrpc"]);
    }
}
