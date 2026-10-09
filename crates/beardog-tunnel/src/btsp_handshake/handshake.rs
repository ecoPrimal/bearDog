// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server-side BTSP handshake orchestrator.
//!
//! Runs the 4-step handshake on a raw stream before any JSON-RPC traffic.

use super::FamilySeed;
use super::crypto::{
    compute_challenge_hmac, derive_handshake_key, generate_ephemeral_keypair,
    verify_challenge_response, x25519_shared_secret,
};
use super::framing::{read_frame, write_frame};
use super::load_cipher_floor;
use super::session::{BtspCipher, BtspSession};
use super::types::{
    BTSP_HANDSHAKE_VERSION, ChallengeResponse, ClientHello, HandshakeComplete, HandshakeError,
    ServerHello,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use beardog_errors::BearDogError;
use rand::RngCore;
use tracing::{debug, warn};

static BTSP_JSONLINE_READ_TIMEOUT: std::sync::LazyLock<std::time::Duration> =
    std::sync::LazyLock::new(|| {
        std::time::Duration::from_secs(
            std::env::var(beardog_config::env_keys::ENV_HANDSHAKE_TIMEOUT_SECS)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        )
    });

/// Run the server side of the BTSP handshake on `stream`.
///
/// On success returns a [`BtspSession`] ready for encrypted frame I/O.
/// On failure writes a [`HandshakeError`] frame and returns `Err`.
///
/// # Errors
///
/// Returns an error if any step of the handshake fails (I/O, crypto, or
/// verification). The caller should close the connection.
pub async fn perform_server_handshake<S>(
    stream: &mut S,
    family_seed: &FamilySeed,
) -> Result<BtspSession, BearDogError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    perform_server_handshake_bound(stream, family_seed, &super::crypto::TransportBinding::NONE)
        .await
}

/// Run the server side of the BTSP handshake with transport/lineage binding.
///
/// Same as [`perform_server_handshake`] but mixes riboCipher signal tier,
/// mitoCipher HMAC tag, and BirdSong lineage material into the session key
/// derivation. The binding is carried through the HKDF info parameter so
/// session keys are cryptographically dependent on HOW the connection was
/// authenticated at every layer.
///
/// # Errors
///
/// Returns an error if any step of the handshake fails.
pub async fn perform_server_handshake_bound<S>(
    stream: &mut S,
    family_seed: &FamilySeed,
    transport_binding: &super::crypto::TransportBinding,
) -> Result<BtspSession, BearDogError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // ── Derive handshake key from family seed ──────────────────────────
    let handshake_key = derive_handshake_key(family_seed.as_bytes())?;

    // ── Step 1: Read ClientHello ───────────────────────────────────────
    let client_hello_bytes = read_frame(stream).await?;
    let client_hello: ClientHello = serde_json::from_slice(&client_hello_bytes)
        .map_err(|e| BearDogError::system(format!("BTSP ClientHello parse failed: {e}")))?;

    if client_hello.version != BTSP_HANDSHAKE_VERSION {
        send_error(stream, "handshake_failed", "unsupported_version").await;
        return Err(BearDogError::system(format!(
            "BTSP version mismatch: client={}, server={}",
            client_hello.version, BTSP_HANDSHAKE_VERSION
        )));
    }

    let client_pub_bytes = BASE64
        .decode(&client_hello.client_ephemeral_pub)
        .map_err(|e| {
            BearDogError::system(format!("BTSP client ephemeral key decode failed: {e}"))
        })?;
    if client_pub_bytes.len() != 32 {
        send_error(stream, "handshake_failed", "invalid_key_length").await;
        return Err(BearDogError::system(
            "BTSP client ephemeral key is not 32 bytes".to_string(),
        ));
    }

    debug!("BTSP handshake: received ClientHello");

    // ── Step 2: Send ServerHello with challenge ────────────────────────
    let (server_secret, server_pub) = generate_ephemeral_keypair();
    let mut challenge = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge);

    let server_hello = ServerHello {
        version: BTSP_HANDSHAKE_VERSION,
        server_ephemeral_pub: BASE64.encode(server_pub.as_bytes()),
        challenge: BASE64.encode(challenge),
    };

    let server_hello_json = serde_json::to_vec(&server_hello)
        .map_err(|e| BearDogError::system(format!("BTSP ServerHello serialize: {e}")))?;
    write_frame(stream, &server_hello_json).await?;

    debug!("BTSP handshake: sent ServerHello");

    // ── Step 3: Read ChallengeResponse ─────────────────────────────────
    let response_bytes = read_frame(stream).await?;
    let response: ChallengeResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| BearDogError::system(format!("BTSP ChallengeResponse parse failed: {e}")))?;

    let client_response = BASE64
        .decode(&response.response)
        .map_err(|e| BearDogError::system(format!("BTSP challenge response decode: {e}")))?;

    // Verify family membership
    if let Err(e) = verify_challenge_response(
        &handshake_key,
        &challenge,
        &client_pub_bytes,
        server_pub.as_bytes(),
        &client_response,
    ) {
        send_error(stream, "handshake_failed", "family_verification").await;
        warn!("BTSP handshake failed: family verification");
        return Err(e);
    }

    debug!("BTSP handshake: challenge verified");

    // ── Negotiate cipher (enforce floor) ────────────────────────────────
    let requested = BtspCipher::from_wire_name(&response.preferred_cipher)
        .unwrap_or(BtspCipher::ChaCha20Poly1305);
    let floor = load_cipher_floor();
    let cipher = if requested.rank() < floor.rank() {
        warn!(
            requested = requested.wire_name(),
            floor = floor.wire_name(),
            "BTSP handshake: client cipher below floor, upgrading"
        );
        floor
    } else {
        requested
    };

    // ── Generate session ID ────────────────────────────────────────────
    let mut session_id_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut session_id_bytes);
    let mut session_id = String::with_capacity(32);
    for b in &session_id_bytes {
        use std::fmt::Write;
        let _ = write!(session_id, "{b:02x}");
    }

    // Server proves family membership to client (mutual auth)
    let server_proof_hmac = compute_challenge_hmac(
        &handshake_key,
        &challenge,
        server_pub.as_bytes(),
        &client_pub_bytes,
    )?;

    // ── Step 4: Send HandshakeComplete ─────────────────────────────────
    let complete = HandshakeComplete {
        cipher: cipher.wire_name().to_string(),
        session_id: session_id.clone(),
        server_proof: BASE64.encode(server_proof_hmac),
    };
    let complete_json = serde_json::to_vec(&complete)
        .map_err(|e| BearDogError::system(format!("BTSP HandshakeComplete serialize: {e}")))?;
    write_frame(stream, &complete_json).await?;

    debug!(session_id = %session_id, cipher = %cipher.wire_name(), "BTSP handshake complete");

    // ── Derive session keys from X25519 shared secret ──────────────────
    // Session keys are bound to the transport authentication layer: the
    // riboCipher signal tier, mitoCipher HMAC tag, and BirdSong lineage
    // material all contribute to the HKDF info, creating a cryptographic
    // chain from transport → handshake → session.
    let client_pub_array: [u8; 32] = client_pub_bytes
        .try_into()
        .map_err(|_| BearDogError::system("BTSP client key length mismatch".to_string()))?;
    let their_pub = x25519_dalek::PublicKey::from(client_pub_array);
    let shared_secret = x25519_shared_secret(&server_secret, &their_pub);
    let keys = super::crypto::derive_session_keys_bound(
        &shared_secret,
        session_id.as_bytes(),
        transport_binding,
    )?;

    let mut session = BtspSession::new_server(
        session_id,
        cipher,
        keys.server_to_client,
        keys.client_to_server,
    );
    session.transport_tier = transport_binding.signal_tier;
    session.lineage_bound = transport_binding.lineage_hash != [0u8; 32];

    Ok(session)
}

/// Best-effort: send a handshake error frame and swallow any I/O error.
async fn send_error<S: tokio::io::AsyncWrite + Unpin>(stream: &mut S, error: &str, reason: &str) {
    let msg = HandshakeError {
        error: error.to_string(),
        reason: reason.to_string(),
    };
    if let Ok(json) = serde_json::to_vec(&msg) {
        let _ = write_frame(stream, &json).await;
    }
}

// ── JSON-line framed handshake (primalSpring / cross-primal UDS) ────────

/// Continue a BTSP handshake from an already-parsed [`ClientHello`] using
/// newline-delimited JSON framing.
///
/// Clients like primalSpring send the `ClientHello` as a JSON line:
///
/// ```text
/// {"protocol":"btsp","version":1,"client_ephemeral_pub":"<b64>"}\n
/// ```
///
/// The caller has already read and parsed this first line for protocol
/// detection; this function handles steps 2–4.
///
/// # Errors
///
/// Returns an error if any handshake step fails (I/O, crypto, or
/// family-membership verification).
pub async fn continue_server_handshake_jsonline<S>(
    stream: &mut S,
    client_hello: &ClientHello,
    family_seed: &FamilySeed,
) -> Result<BtspSession, BearDogError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    continue_server_handshake_jsonline_bound(
        stream,
        client_hello,
        family_seed,
        &super::crypto::TransportBinding::NONE,
    )
    .await
}

/// JSON-line BTSP handshake with transport/lineage binding.
///
/// See [`continue_server_handshake_jsonline`] — this variant mixes
/// riboCipher and BirdSong lineage material into session key derivation.
///
/// # Errors
///
/// Returns an error if any handshake step fails.
pub async fn continue_server_handshake_jsonline_bound<S>(
    stream: &mut S,
    client_hello: &ClientHello,
    family_seed: &FamilySeed,
    transport_binding: &super::crypto::TransportBinding,
) -> Result<BtspSession, BearDogError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let handshake_key = derive_handshake_key(family_seed.as_bytes())?;

    if client_hello.version != BTSP_HANDSHAKE_VERSION {
        send_error_jsonline(stream, "handshake_failed", "unsupported_version").await;
        return Err(BearDogError::system(format!(
            "BTSP version mismatch: client={}, server={}",
            client_hello.version, BTSP_HANDSHAKE_VERSION
        )));
    }

    let client_pub_bytes = BASE64
        .decode(&client_hello.client_ephemeral_pub)
        .map_err(|e| {
            BearDogError::system(format!("BTSP client ephemeral key decode failed: {e}"))
        })?;
    if client_pub_bytes.len() != 32 {
        send_error_jsonline(stream, "handshake_failed", "invalid_key_length").await;
        return Err(BearDogError::system(
            "BTSP client ephemeral key is not 32 bytes".to_string(),
        ));
    }

    debug!("BTSP handshake (JSON-line): validated ClientHello");

    // ── Step 2: Send ServerHello ────────────────────────────────────────
    let (server_secret, server_pub) = generate_ephemeral_keypair();
    let mut challenge = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge);

    let mut session_id_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut session_id_bytes);
    let mut session_id = String::with_capacity(32);
    for b in &session_id_bytes {
        use std::fmt::Write;
        let _ = write!(session_id, "{b:02x}");
    }

    let server_hello = serde_json::json!({
        "version": BTSP_HANDSHAKE_VERSION,
        "server_ephemeral_pub": BASE64.encode(server_pub.as_bytes()),
        "challenge": BASE64.encode(challenge),
        "session_id": &session_id,
    });
    write_jsonline(stream, &server_hello).await?;
    debug!("BTSP handshake (JSON-line): sent ServerHello");

    // ── Step 3: Read ChallengeResponse ──────────────────────────────────
    let response_bytes = read_jsonline(stream).await?;
    let response: ChallengeResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| BearDogError::system(format!("BTSP ChallengeResponse parse: {e}")))?;

    let client_response = BASE64
        .decode(&response.response)
        .map_err(|e| BearDogError::system(format!("BTSP challenge response decode: {e}")))?;

    if let Err(e) = verify_challenge_response(
        &handshake_key,
        &challenge,
        &client_pub_bytes,
        server_pub.as_bytes(),
        &client_response,
    ) {
        send_error_jsonline(stream, "handshake_failed", "family_verification").await;
        warn!("BTSP handshake (JSON-line): family verification failed");
        return Err(e);
    }

    debug!("BTSP handshake (JSON-line): challenge verified");

    // ── Negotiate cipher ────────────────────────────────────────────────
    let cipher = BtspCipher::from_wire_name(&response.preferred_cipher)
        .unwrap_or(BtspCipher::ChaCha20Poly1305);

    // ── Step 4: Send HandshakeComplete ──────────────────────────────────
    let complete = serde_json::json!({
        "status": "ok",
        "session_id": &session_id,
        "cipher": cipher.wire_name(),
    });
    write_jsonline(stream, &complete).await?;

    debug!(
        session_id = %session_id,
        cipher = %cipher.wire_name(),
        "BTSP handshake (JSON-line) complete"
    );

    // ── Derive session keys (transport + lineage bound) ────────────────
    let client_pub_array: [u8; 32] = client_pub_bytes
        .try_into()
        .map_err(|_| BearDogError::system("BTSP client key length mismatch".to_string()))?;
    let their_pub = x25519_dalek::PublicKey::from(client_pub_array);
    let shared_secret = x25519_shared_secret(&server_secret, &their_pub);
    let keys = super::crypto::derive_session_keys_bound(
        &shared_secret,
        session_id.as_bytes(),
        transport_binding,
    )?;

    let mut session = BtspSession::new_server(
        session_id,
        cipher,
        keys.server_to_client,
        keys.client_to_server,
    );
    session.transport_tier = transport_binding.signal_tier;
    session.lineage_bound = transport_binding.lineage_hash != [0u8; 32];

    Ok(session)
}

/// Write a JSON value as a newline-terminated line.
async fn write_jsonline<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    value: &serde_json::Value,
) -> Result<(), BearDogError> {
    use tokio::io::AsyncWriteExt;
    let mut buf = serde_json::to_vec(value)
        .map_err(|e| BearDogError::system(format!("BTSP JSON-line serialize: {e}")))?;
    buf.push(b'\n');
    stream
        .write_all(&buf)
        .await
        .map_err(|e| BearDogError::system(format!("BTSP JSON-line write: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| BearDogError::system(format!("BTSP JSON-line flush: {e}")))?;
    Ok(())
}

const BTSP_MAX_JSONLINE_BYTES: usize = 64 * 1024;

/// Read bytes until a newline delimiter, with a 30-second deadline.
///
/// Uses byte-at-a-time reads to avoid `BufReader` ownership issues during
/// the handshake (only one read per handshake, so throughput is irrelevant).
async fn read_jsonline<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Vec<u8>, BearDogError> {
    use tokio::io::AsyncReadExt;
    let deadline = tokio::time::Instant::now() + *BTSP_JSONLINE_READ_TIMEOUT;
    let mut buf = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        tokio::time::timeout_at(deadline, stream.read_exact(&mut byte))
            .await
            .map_err(|_| BearDogError::system("BTSP JSON-line read timed out".to_string()))?
            .map_err(|e| BearDogError::system(format!("BTSP JSON-line read: {e}")))?;
        if byte[0] == b'\n' {
            return Ok(buf);
        }
        buf.push(byte[0]);
        if buf.len() > BTSP_MAX_JSONLINE_BYTES {
            return Err(BearDogError::system(
                "BTSP JSON-line message exceeds 64 KiB".to_string(),
            ));
        }
    }
}

/// Best-effort JSON-line error (swallows I/O failures).
async fn send_error_jsonline<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    error: &str,
    reason: &str,
) {
    let msg = serde_json::json!({"error": error, "reason": reason});
    let _ = write_jsonline(stream, &msg).await;
}

#[cfg(test)]
mod tests {
    #![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, reason = "expect/unwrap acceptable for invariant failures in tests and bootstrap code"))]

    use super::*;

    #[tokio::test]
    async fn jsonline_handshake_null_cipher() {
        let seed = FamilySeed::new(b"test-family-seed-exactly-32byte!".to_vec());
        let (mut client, mut server) = tokio::io::duplex(16384);

        let (_client_secret, client_pub) = generate_ephemeral_keypair();

        let hello = ClientHello {
            version: BTSP_HANDSHAKE_VERSION,
            client_ephemeral_pub: BASE64.encode(client_pub.as_bytes()),
        };
        let seed_clone = FamilySeed::new(seed.as_bytes().to_vec());

        let server_fut = continue_server_handshake_jsonline(&mut server, &hello, &seed);

        let client_fut = async {
            let sh_bytes = read_jsonline(&mut client).await.expect("ServerHello");
            let sh: serde_json::Value =
                serde_json::from_slice(&sh_bytes).expect("parse ServerHello");

            let server_pub_b64 = sh["server_ephemeral_pub"].as_str().unwrap();
            let challenge_b64 = sh["challenge"].as_str().unwrap();
            let server_pub_bytes = BASE64.decode(server_pub_b64).unwrap();
            let challenge_bytes = BASE64.decode(challenge_b64).unwrap();

            let hk = derive_handshake_key(seed_clone.as_bytes()).unwrap();
            let hmac = compute_challenge_hmac(
                &hk,
                &challenge_bytes,
                client_pub.as_bytes(),
                &server_pub_bytes,
            )
            .unwrap();

            let cr = serde_json::json!({
                "response": BASE64.encode(hmac),
                "preferred_cipher": "null",
            });
            write_jsonline(&mut client, &cr).await.expect("write CR");

            let complete_bytes = read_jsonline(&mut client).await.expect("Complete");
            let complete: serde_json::Value =
                serde_json::from_slice(&complete_bytes).expect("parse Complete");
            assert_eq!(complete["status"].as_str(), Some("ok"));
            assert_eq!(complete["cipher"].as_str(), Some("null"));
        };

        let (session_result, ()) = tokio::join!(server_fut, client_fut);
        let session = session_result.expect("handshake should succeed");
        assert_eq!(session.cipher, BtspCipher::Null);
    }

    #[tokio::test]
    async fn jsonline_handshake_rejects_bad_version() {
        let seed = FamilySeed::new(b"test-family-seed-exactly-32byte!".to_vec());
        let (mut _client, mut server) = tokio::io::duplex(16384);

        let hello = ClientHello {
            version: 999,
            client_ephemeral_pub: BASE64.encode([0u8; 32]),
        };
        let result = continue_server_handshake_jsonline(&mut server, &hello, &seed).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn jsonline_handshake_rejects_short_key() {
        let seed = FamilySeed::new(b"test-family-seed-exactly-32byte!".to_vec());
        let (mut _client, mut server) = tokio::io::duplex(16384);

        let hello = ClientHello {
            version: BTSP_HANDSHAKE_VERSION,
            client_ephemeral_pub: BASE64.encode([0u8; 16]),
        };
        let result = continue_server_handshake_jsonline(&mut server, &hello, &seed).await;
        assert!(result.is_err());
    }
}
