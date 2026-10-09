// SPDX-License-Identifier: AGPL-3.0-or-later

//! BTSP handshake cryptographic primitives.
//!
//! Key derivation follows `BTSP_PROTOCOL_STANDARD.md §Key Derivation`:
//!
//! ```text
//! handshake_key  = HKDF-SHA256(ikm=family_seed, salt="btsp-v1", info="handshake")
//! shared_secret  = X25519(our_ephemeral, their_pub)
//! session_keys   = HKDF(shared_secret, "btsp-session-v1", session_id)
//! ```

use beardog_errors::BearDogError;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

fn new_hmac(key: &[u8]) -> Result<HmacSha256, BearDogError> {
    HmacSha256::new_from_slice(key)
        .map_err(|e| BearDogError::system(format!("BTSP HMAC key error: {e}")))
}

/// Derive the handshake key from the family seed.
///
/// `HKDF-SHA256(ikm=family_seed, salt="btsp-v1", info="handshake")` → 32 bytes.
///
/// # Errors
///
/// Returns an error if HKDF expansion fails (should not happen with valid inputs).
pub fn derive_handshake_key(family_seed: &[u8]) -> Result<[u8; 32], BearDogError> {
    let hk = Hkdf::<Sha256>::new(Some(b"btsp-v1"), family_seed);
    let mut okm = [0u8; 32];
    hk.expand(b"handshake", &mut okm).map_err(|e| {
        BearDogError::system(format!("BTSP HKDF handshake key derivation failed: {e}"))
    })?;
    Ok(okm)
}

/// Compute the challenge response HMAC.
///
/// `HMAC-SHA256(key=handshake_key, data=challenge || client_pub || server_pub)`
///
/// # Errors
///
/// Returns an error if the HMAC key length is invalid.
pub fn compute_challenge_hmac(
    handshake_key: &[u8; 32],
    challenge: &[u8],
    client_pub: &[u8],
    server_pub: &[u8],
) -> Result<[u8; 32], BearDogError> {
    let mut mac = new_hmac(handshake_key)?;
    mac.update(challenge);
    mac.update(client_pub);
    mac.update(server_pub);
    let result = mac.finalize();
    Ok(result.into_bytes().into())
}

/// Verify a client's challenge response in constant time.
///
/// # Errors
///
/// Returns an error if the HMAC computation itself fails or if
/// the response does not match (family membership verification failure).
pub fn verify_challenge_response(
    handshake_key: &[u8; 32],
    challenge: &[u8],
    client_pub: &[u8],
    server_pub: &[u8],
    client_response: &[u8],
) -> Result<(), BearDogError> {
    let expected = compute_challenge_hmac(handshake_key, challenge, client_pub, server_pub)?;

    if client_response.len() != 32 || expected.ct_eq(client_response).unwrap_u8() != 1 {
        return Err(BearDogError::security(
            "BTSP handshake failed: family_verification".to_string(),
        ));
    }
    Ok(())
}
/// Generate an X25519 ephemeral keypair for forward secrecy.
#[must_use]
pub fn generate_ephemeral_keypair() -> (StaticSecret, PublicKey) {
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}
/// Compute the X25519 shared secret.
#[must_use]
pub fn x25519_shared_secret(our_secret: &StaticSecret, their_public: &PublicKey) -> [u8; 32] {
    *our_secret.diffie_hellman(their_public).as_bytes()
}

/// Derive directional session keys from the X25519 shared secret.
///
/// ```text
/// HKDF-SHA256(ikm=shared_secret, salt="btsp-session-v1", info=session_id)
///   → 64 bytes split into (server_to_client_key[32], client_to_server_key[32])
/// ```
///
/// # Errors
///
/// Returns an error if HKDF expansion fails.
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    session_id: &[u8],
) -> Result<SessionKeys, BearDogError> {
    derive_session_keys_bound(shared_secret, session_id, &TransportBinding::NONE)
}

/// Transport binding context — carries riboCipher signal tier and mito/lineage
/// material into BTSP session key derivation.
///
/// When BTSP is entered via a riboCipher signal, the signal tier and any
/// associated authentication material (mito HMAC tag, lineage proof) are
/// cryptographically bound into the session keys via the HKDF info parameter.
/// This ensures the session keys differ based on HOW the connection was
/// authenticated at the transport layer — a session entered via mitoCipher
/// produces different keys than one entered via clear signal or no signal.
///
/// # Wire Format Binding
///
/// ```text
/// info = session_id || transport_tag
/// transport_tag = [tier_byte, proto_byte, mito_tag[4], lineage_hash[32]]
///               = 38 bytes (or 0 bytes when NONE)
/// ```
pub struct TransportBinding {
    /// riboCipher signal tier: 0xEC (clear), 0xED (mito), 0xEE (nuclear), 0x00 (none).
    pub signal_tier: u8,
    /// Protocol type byte from the riboCipher signal (e.g. `PROTO_BTSP_BINARY`).
    pub protocol_type: u8,
    /// 4-byte mito HMAC tag (all zeros for clear/none tier).
    pub mito_tag: [u8; 4],
    /// 32-byte BLAKE3 hash of lineage proof material from BirdSong genetics.
    /// All zeros when no lineage material is available.
    pub lineage_hash: [u8; 32],
}

impl TransportBinding {
    /// No transport binding — legacy connections without riboCipher signal.
    pub const NONE: Self = Self {
        signal_tier: 0x00,
        protocol_type: 0x00,
        mito_tag: [0u8; 4],
        lineage_hash: [0u8; 32],
    };

    /// Build a binding from a clear riboCipher signal.
    #[must_use]
    pub const fn clear(protocol_type: u8) -> Self {
        Self {
            signal_tier: 0xEC,
            protocol_type,
            mito_tag: [0u8; 4],
            lineage_hash: [0u8; 32],
        }
    }

    /// Build a binding from a mito-obfuscated riboCipher signal.
    #[must_use]
    pub const fn mito(protocol_type: u8, mito_tag: [u8; 4]) -> Self {
        Self {
            signal_tier: 0xED,
            protocol_type,
            mito_tag,
            lineage_hash: [0u8; 32],
        }
    }

    /// Attach BirdSong lineage hash to an existing binding.
    #[must_use]
    pub const fn with_lineage(mut self, lineage_hash: [u8; 32]) -> Self {
        self.lineage_hash = lineage_hash;
        self
    }

    /// Serialize the binding as a fixed-length tag for HKDF info mixing.
    /// Returns empty slice for `NONE` (backward compatible with unbound sessions).
    fn as_tag(&self) -> Vec<u8> {
        if self.signal_tier == 0x00
            && self.mito_tag == [0u8; 4]
            && self.lineage_hash == [0u8; 32]
        {
            return Vec::new();
        }
        let mut tag = Vec::with_capacity(38);
        tag.push(self.signal_tier);
        tag.push(self.protocol_type);
        tag.extend_from_slice(&self.mito_tag);
        tag.extend_from_slice(&self.lineage_hash);
        tag
    }
}

/// Derive directional session keys with transport and lineage binding.
///
/// Extends the standard `derive_session_keys` by mixing the [`TransportBinding`]
/// into the HKDF info parameter. This cryptographically binds the riboCipher
/// signal tier, mito authentication tag, and BirdSong lineage material into the
/// session keys — ensuring that BOTH the IPC transport authentication (riboCipher
/// + mitoCipher) and the genetic identity (BirdSong lineage) contribute to the
/// session's cryptographic foundation.
///
/// ```text
/// HKDF-SHA256(
///     ikm  = shared_secret,
///     salt = "btsp-session-v2",
///     info = session_id || transport_tag,
/// ) → 64 bytes → (server_to_client[32], client_to_server[32])
/// ```
///
/// When `binding` is `TransportBinding::NONE`, falls back to v1 salt for
/// backward compatibility with unbound sessions.
///
/// # Errors
///
/// Returns an error if HKDF expansion fails.
pub fn derive_session_keys_bound(
    shared_secret: &[u8; 32],
    session_id: &[u8],
    binding: &TransportBinding,
) -> Result<SessionKeys, BearDogError> {
    let transport_tag = binding.as_tag();

    let salt = if transport_tag.is_empty() {
        b"btsp-session-v1".as_slice()
    } else {
        b"btsp-session-v2".as_slice()
    };

    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);

    let mut info = Vec::with_capacity(session_id.len() + transport_tag.len());
    info.extend_from_slice(session_id);
    info.extend_from_slice(&transport_tag);

    let mut okm = [0u8; 64];
    hk.expand(&info, &mut okm)
        .map_err(|e| BearDogError::system(format!("BTSP session key derivation failed: {e}")))?;

    let mut server_to_client = [0u8; 32];
    let mut client_to_server = [0u8; 32];
    server_to_client.copy_from_slice(&okm[..32]);
    client_to_server.copy_from_slice(&okm[32..]);

    Ok(SessionKeys {
        server_to_client,
        client_to_server,
    })
}

/// Pair of directional session keys.
pub struct SessionKeys {
    /// Key for server-to-client traffic.
    pub server_to_client: [u8; 32],
    /// Key for client-to-server traffic.
    pub client_to_server: [u8; 32],
}

/// Derive Phase 3 directional session keys from the handshake key and nonces.
///
/// ```text
/// HKDF-SHA256(ikm = handshake_key, salt = client_nonce || server_nonce)
///   info = "btsp-session-v1-c2s" → client_to_server key (32 bytes)
///   info = "btsp-session-v1-s2c" → server_to_client key (32 bytes)
/// ```
///
/// The `is_server` flag mirrors the keys: the server's encrypt key is
/// `server_to_client`, and its decrypt key is `client_to_server`.
///
/// # Errors
///
/// Returns an error if HKDF expansion fails.
pub fn derive_phase3_session_keys(
    handshake_key: &[u8; 32],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> Result<Phase3SessionKeys, BearDogError> {
    let mut salt = Vec::with_capacity(client_nonce.len() + server_nonce.len());
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), handshake_key);

    let mut client_to_server = [0u8; 32];
    hk.expand(b"btsp-session-v1-c2s", &mut client_to_server)
        .map_err(|e| BearDogError::system(format!("BTSP Phase 3 HKDF c2s: {e}")))?;

    let mut server_to_client = [0u8; 32];
    hk.expand(b"btsp-session-v1-s2c", &mut server_to_client)
        .map_err(|e| BearDogError::system(format!("BTSP Phase 3 HKDF s2c: {e}")))?;

    Ok(Phase3SessionKeys {
        encrypt_key: server_to_client,
        decrypt_key: client_to_server,
    })
}

/// Directional session keys for Phase 3 encrypted channel (server perspective).
///
/// The server encrypts with `server_to_client` and decrypts with `client_to_server`.
pub struct Phase3SessionKeys {
    /// Key for encrypting server → client traffic.
    pub encrypt_key: [u8; 32],
    /// Key for decrypting client → server traffic.
    pub decrypt_key: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_key_is_deterministic() {
        let seed = b"test-family-seed-32-bytes-long!!";
        let k1 = derive_handshake_key(seed).expect("derive 1");
        let k2 = derive_handshake_key(seed).expect("derive 2");
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let k1 = derive_handshake_key(b"seed-alpha").expect("alpha");
        let k2 = derive_handshake_key(b"seed-bravo").expect("bravo");
        assert_ne!(k1, k2);
    }

    #[test]
    fn hmac_roundtrip_verify() {
        let hk = [0xAA; 32];
        let challenge = b"random-challenge-bytes";
        let client_pub = b"client-pub-placeholder-32-bytes!";
        let server_pub = b"server-pub-placeholder-32-bytes!";

        let mac = compute_challenge_hmac(&hk, challenge, client_pub, server_pub).expect("compute");
        verify_challenge_response(&hk, challenge, client_pub, server_pub, &mac).expect("verify");
    }

    #[test]
    fn hmac_rejects_wrong_response() {
        let hk = [0xAA; 32];
        let challenge = b"challenge";
        let client_pub = b"cpub";
        let server_pub = b"spub";
        let bad = [0xBB; 32];

        let result = verify_challenge_response(&hk, challenge, client_pub, server_pub, &bad);
        assert!(result.is_err());
    }

    #[test]
    fn x25519_shared_secret_agreement() {
        let (secret_a, pub_a) = generate_ephemeral_keypair();
        let (secret_b, pub_b) = generate_ephemeral_keypair();

        let shared_ab = x25519_shared_secret(&secret_a, &pub_b);
        let shared_ba = x25519_shared_secret(&secret_b, &pub_a);
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn session_keys_are_deterministic_for_same_inputs() {
        let shared = [0x42; 32];
        let sid = b"session-id-hex";
        let k1 = derive_session_keys(&shared, sid).expect("k1");
        let k2 = derive_session_keys(&shared, sid).expect("k2");
        assert_eq!(k1.server_to_client, k2.server_to_client);
        assert_eq!(k1.client_to_server, k2.client_to_server);
    }

    #[test]
    fn session_keys_directions_differ() {
        let shared = [0x42; 32];
        let sid = b"sid";
        let keys = derive_session_keys(&shared, sid).expect("keys");
        assert_ne!(keys.server_to_client, keys.client_to_server);
    }

    #[test]
    fn phase3_keys_deterministic() {
        let hk = [0xAA; 32];
        let cn = [0xBB; 32];
        let sn = [0xCC; 32];
        let k1 = derive_phase3_session_keys(&hk, &cn, &sn).expect("k1");
        let k2 = derive_phase3_session_keys(&hk, &cn, &sn).expect("k2");
        assert_eq!(k1.encrypt_key, k2.encrypt_key);
        assert_eq!(k1.decrypt_key, k2.decrypt_key);
    }

    #[test]
    fn phase3_keys_directions_differ() {
        let hk = [0x42; 32];
        let cn = [0x01; 32];
        let sn = [0x02; 32];
        let keys = derive_phase3_session_keys(&hk, &cn, &sn).expect("keys");
        assert_ne!(keys.encrypt_key, keys.decrypt_key);
    }

    #[test]
    fn phase3_keys_nonzero() {
        let hk = [0xDE; 32];
        let cn = [0xAD; 32];
        let sn = [0xBE; 32];
        let keys = derive_phase3_session_keys(&hk, &cn, &sn).expect("keys");
        assert_ne!(keys.encrypt_key, [0u8; 32]);
        assert_ne!(keys.decrypt_key, [0u8; 32]);
    }

    #[test]
    fn phase3_different_nonces_produce_different_keys() {
        let hk = [0x42; 32];
        let cn = [0x01; 32];
        let sn_a = [0x02; 32];
        let sn_b = [0x03; 32];
        let ka = derive_phase3_session_keys(&hk, &cn, &sn_a).expect("ka");
        let kb = derive_phase3_session_keys(&hk, &cn, &sn_b).expect("kb");
        assert_ne!(ka.encrypt_key, kb.encrypt_key);
    }

    #[test]
    fn verify_challenge_rejects_non_32_byte_response() {
        let hk = [0x55; 32];
        let challenge = b"chal";
        let cp = [0u8; 32];
        let sp = [0u8; 32];
        let short = [0u8; 31];
        let err = verify_challenge_response(&hk, challenge, &cp, &sp, &short).expect_err("short");
        assert!(err.to_string().contains("family") || err.to_string().contains("verification"));
    }

    // ── TransportBinding tests ─────────────────────────────────────────

    #[test]
    fn transport_binding_none_produces_empty_tag() {
        assert!(TransportBinding::NONE.as_tag().is_empty());
    }

    #[test]
    fn transport_binding_clear_produces_38_byte_tag() {
        let b = TransportBinding::clear(0x02);
        let tag = b.as_tag();
        assert_eq!(tag.len(), 38);
        assert_eq!(tag[0], 0xEC); // signal tier
        assert_eq!(tag[1], 0x02); // protocol type
        assert_eq!(&tag[2..6], &[0u8; 4]); // no mito tag
        assert_eq!(&tag[6..38], &[0u8; 32]); // no lineage
    }

    #[test]
    fn transport_binding_mito_carries_tag() {
        let mito_tag = [0xDE, 0xAD, 0xBE, 0xEF];
        let b = TransportBinding::mito(0x02, mito_tag);
        let tag = b.as_tag();
        assert_eq!(tag[0], 0xED); // mito tier
        assert_eq!(&tag[2..6], &mito_tag);
    }

    #[test]
    fn transport_binding_with_lineage_fills_tail() {
        let lineage = [0x42u8; 32];
        let b = TransportBinding::clear(0x02).with_lineage(lineage);
        let tag = b.as_tag();
        assert_eq!(&tag[6..38], &lineage);
    }

    #[test]
    fn bound_keys_differ_from_unbound() {
        let shared = [0x42; 32];
        let sid = b"session-id";

        let unbound = derive_session_keys(&shared, sid).expect("unbound");
        let bound = derive_session_keys_bound(
            &shared,
            sid,
            &TransportBinding::clear(0x02),
        )
        .expect("bound");

        // Different salt ("btsp-session-v1" vs "btsp-session-v2") + different
        // info (session_id vs session_id || transport_tag) → different keys.
        assert_ne!(unbound.server_to_client, bound.server_to_client);
        assert_ne!(unbound.client_to_server, bound.client_to_server);
    }

    #[test]
    fn bound_keys_differ_by_tier() {
        let shared = [0x42; 32];
        let sid = b"session-id";

        let clear = derive_session_keys_bound(
            &shared,
            sid,
            &TransportBinding::clear(0x02),
        )
        .expect("clear");

        let mito = derive_session_keys_bound(
            &shared,
            sid,
            &TransportBinding::mito(0x02, [0xAA; 4]),
        )
        .expect("mito");

        assert_ne!(clear.server_to_client, mito.server_to_client);
    }

    #[test]
    fn bound_keys_differ_by_lineage() {
        let shared = [0x42; 32];
        let sid = b"session-id";

        let no_lineage = derive_session_keys_bound(
            &shared,
            sid,
            &TransportBinding::clear(0x02),
        )
        .expect("no_lineage");

        let with_lineage = derive_session_keys_bound(
            &shared,
            sid,
            &TransportBinding::clear(0x02).with_lineage([0xFF; 32]),
        )
        .expect("with_lineage");

        assert_ne!(no_lineage.server_to_client, with_lineage.server_to_client);
    }

    #[test]
    fn bound_none_matches_unbound() {
        let shared = [0x42; 32];
        let sid = b"session-id";

        let unbound = derive_session_keys(&shared, sid).expect("unbound");
        let bound_none = derive_session_keys_bound(
            &shared,
            sid,
            &TransportBinding::NONE,
        )
        .expect("bound_none");

        // NONE binding falls back to v1 salt → same keys as unbound
        assert_eq!(unbound.server_to_client, bound_none.server_to_client);
        assert_eq!(unbound.client_to_server, bound_none.client_to_server);
    }
}
