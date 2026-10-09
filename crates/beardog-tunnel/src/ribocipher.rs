// SPDX-License-Identifier: AGPL-3.0-or-later

//! riboCipher — Transport Signal Standard (Wave 111)
//!
//! Deterministic protocol routing via intentional signal prefix. Replaces
//! fragile peek-and-guess detection where servers read the first byte and
//! hope to classify the connection.
//!
//! # Wire Format
//!
//! ## Tier 1: Clear Signal (local same-gate IPC)
//! ```text
//! [0xEC][protocol_type: u8]
//! ```
//!
//! ## Tier 2: Mito-Obfuscated (cross-gate / WAN)
//! ```text
//! [0xED][hmac_tag: [u8; 4]]
//! ```
//!
//! ## Tier 3: Nuclear-Sealed (privileged)
//! ```text
//! [0xEE][encrypted_payload: [u8; 6]]
//! ```
//!
//! ## Legacy (deprecated)
//! Any connection NOT starting with 0xEC/0xED/0xEE logs WARN and falls
//! through to existing peek logic during the deprecation window.

use std::sync::atomic::{AtomicU64, Ordering};

pub use beardog_types::constants::domains::network::ribocipher::{
    PROTO_BTSP_BINARY, PROTO_BTSP_JSONLINE, PROTO_DARK_FOREST_BEACON, PROTO_ENCRYPTED_RESUME,
    PROTO_HTTP, PROTO_MESH_RELAY, PROTO_NDJSON_JSONRPC, PROTO_PROBE, SIGNAL_CLEAR, SIGNAL_MITO,
    SIGNAL_NUCLEAR, clear_signal,
};

// ── riboCipher enforcement tracking ─────────────────────────────────
//
// Count connections by signal tier to track migration progress.
// When UNSIGNALLED_CONNECTIONS stays at 0 long enough, the `{` bypass
// can be removed and `BEARDOG_UDS_REQUIRE_BTSP=1` becomes the default.

/// Connections that arrived with a riboCipher signal prefix (0xEC/0xED/0xEE).
pub static SIGNALLED_CONNECTIONS: AtomicU64 = AtomicU64::new(0);

/// Connections that arrived without any riboCipher signal (first byte = `{`).
pub static UNSIGNALLED_CONNECTIONS: AtomicU64 = AtomicU64::new(0);

/// Record a connection that sent a riboCipher signal.
pub fn record_signalled() {
    SIGNALLED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
}

/// Record a connection that did NOT send a riboCipher signal.
pub fn record_unsignalled() {
    UNSIGNALLED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot of riboCipher enforcement progress.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RiboCipherMetrics {
    pub signalled: u64,
    pub unsignalled: u64,
    pub enforcement_ready: bool,
}

/// Get current riboCipher enforcement metrics.
#[must_use]
pub fn enforcement_metrics() -> RiboCipherMetrics {
    let signalled = SIGNALLED_CONNECTIONS.load(Ordering::Relaxed);
    let unsignalled = UNSIGNALLED_CONNECTIONS.load(Ordering::Relaxed);
    RiboCipherMetrics {
        signalled,
        unsignalled,
        enforcement_ready: unsignalled == 0 && signalled > 0,
    }
}

/// Result of riboCipher signal detection on a connection's first bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalResult {
    /// Clear signal detected — protocol type decoded.
    Clear(u8),
    /// Mito-obfuscated signal detected (4-byte HMAC tag follows).
    /// Decoding deferred to caller with family seed.
    Mito([u8; 4]),
    /// Nuclear-sealed signal detected (6-byte encrypted payload follows).
    Nuclear([u8; 6]),
    /// No riboCipher signal — legacy unsignalled connection.
    Legacy(u8),
}

/// Check whether the first byte is a riboCipher signal prefix.
#[must_use]
pub const fn is_signal_byte(byte: u8) -> bool {
    matches!(byte, SIGNAL_CLEAR | SIGNAL_MITO | SIGNAL_NUCLEAR)
}

/// All known protocol types for mito-beacon brute-force decode.
const KNOWN_PROTOS: [u8; 8] = [
    PROTO_PROBE,
    PROTO_NDJSON_JSONRPC,
    PROTO_BTSP_BINARY,
    PROTO_BTSP_JSONLINE,
    PROTO_HTTP,
    PROTO_ENCRYPTED_RESUME,
    PROTO_DARK_FOREST_BEACON,
    PROTO_MESH_RELAY,
];

/// Compute the 4-byte HMAC tag for a mito-beacon signal.
///
/// `HMAC-SHA256(family_seed, &[protocol_type])` truncated to 4 bytes.
/// Both sender and receiver use this — sender to build the tag, receiver
/// to verify by iterating known protocol types.
#[must_use]
pub fn mito_tag(family_seed: &[u8], protocol_type: u8) -> [u8; 4] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let Ok(mut mac) = HmacSha256::new_from_slice(family_seed) else {
        return [0u8; 4];
    };
    mac.update(&[protocol_type]);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; 4];
    tag.copy_from_slice(&result[..4]);
    tag
}

/// Build a 5-byte mito-beacon signal for outbound cross-gate connections.
///
/// Wire format: `[0xED][hmac_tag: 4 bytes]`
#[must_use]
pub fn mito_signal(family_seed: &[u8], protocol_type: u8) -> [u8; 5] {
    let tag = mito_tag(family_seed, protocol_type);
    [SIGNAL_MITO, tag[0], tag[1], tag[2], tag[3]]
}

/// Decode a 4-byte mito-beacon HMAC tag back to a protocol type.
///
/// Iterates all known protocol types, computes `mito_tag` for each, and
/// returns the first match. Returns `None` if no known protocol produces
/// the given tag (invalid seed or unknown protocol).
#[must_use]
pub fn decode_mito_tag(family_seed: &[u8], tag: &[u8; 4]) -> Option<u8> {
    KNOWN_PROTOS
        .iter()
        .find(|&&proto| mito_tag(family_seed, proto) == *tag)
        .copied()
}

/// Human-readable name for a protocol type byte.
#[must_use]
pub const fn protocol_name(proto: u8) -> &'static str {
    match proto {
        PROTO_PROBE => "probe",
        PROTO_NDJSON_JSONRPC => "ndjson-jsonrpc",
        PROTO_BTSP_BINARY => "btsp-binary",
        PROTO_BTSP_JSONLINE => "btsp-jsonline",
        PROTO_HTTP => "http",
        PROTO_ENCRYPTED_RESUME => "encrypted-resume",
        PROTO_DARK_FOREST_BEACON => "dark-forest-beacon",
        PROTO_MESH_RELAY => "mesh-relay",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_bytes_are_sequential_and_non_ascii() {
        assert_eq!(SIGNAL_CLEAR, 0xEC);
        assert_eq!(SIGNAL_MITO, 0xED);
        assert_eq!(SIGNAL_NUCLEAR, 0xEE);
        assert!(!SIGNAL_CLEAR.is_ascii());
        assert!(!SIGNAL_MITO.is_ascii());
        assert!(!SIGNAL_NUCLEAR.is_ascii());
    }

    #[test]
    fn signal_bytes_never_collide_with_json_or_http() {
        assert_ne!(SIGNAL_CLEAR, b'{');
        assert_ne!(SIGNAL_CLEAR, b'G');
        assert_ne!(SIGNAL_CLEAR, b'P');
        assert_ne!(SIGNAL_CLEAR, b'H');
        assert_ne!(SIGNAL_CLEAR, 0x00);
    }

    #[test]
    fn is_signal_byte_detects_all_tiers() {
        assert!(is_signal_byte(SIGNAL_CLEAR));
        assert!(is_signal_byte(SIGNAL_MITO));
        assert!(is_signal_byte(SIGNAL_NUCLEAR));
        assert!(!is_signal_byte(b'{'));
        assert!(!is_signal_byte(0x00));
        assert!(!is_signal_byte(b'G'));
    }

    #[test]
    fn clear_signal_builds_correct_prefix() {
        assert_eq!(clear_signal(PROTO_NDJSON_JSONRPC), [0xEC, 0x01]);
        assert_eq!(clear_signal(PROTO_BTSP_BINARY), [0xEC, 0x02]);
    }

    #[test]
    fn protocol_names_cover_known_types() {
        assert_eq!(protocol_name(PROTO_NDJSON_JSONRPC), "ndjson-jsonrpc");
        assert_eq!(protocol_name(PROTO_BTSP_BINARY), "btsp-binary");
        assert_eq!(protocol_name(0xFF), "unknown");
    }

    #[test]
    fn mito_tag_is_deterministic() {
        let seed = b"test-family-seed-32-bytes!!!!!!!";
        let t1 = mito_tag(seed, PROTO_NDJSON_JSONRPC);
        let t2 = mito_tag(seed, PROTO_NDJSON_JSONRPC);
        assert_eq!(t1, t2);
    }

    #[test]
    fn mito_tag_differs_by_protocol() {
        let seed = b"test-family-seed-32-bytes!!!!!!!";
        let t_json = mito_tag(seed, PROTO_NDJSON_JSONRPC);
        let t_btsp = mito_tag(seed, PROTO_BTSP_BINARY);
        let t_probe = mito_tag(seed, PROTO_PROBE);
        assert_ne!(t_json, t_btsp);
        assert_ne!(t_json, t_probe);
        assert_ne!(t_btsp, t_probe);
    }

    #[test]
    fn mito_tag_differs_by_seed() {
        let seed_a = b"seed-alpha-32-bytes-padding!!!!";
        let seed_b = b"seed-bravo-32-bytes-padding!!!!";
        let t_a = mito_tag(seed_a, PROTO_NDJSON_JSONRPC);
        let t_b = mito_tag(seed_b, PROTO_NDJSON_JSONRPC);
        assert_ne!(t_a, t_b);
    }

    #[test]
    fn mito_signal_builds_correct_wire_format() {
        let seed = b"test-family-seed-32-bytes!!!!!!!";
        let sig = mito_signal(seed, PROTO_NDJSON_JSONRPC);
        assert_eq!(sig[0], SIGNAL_MITO);
        let expected_tag = mito_tag(seed, PROTO_NDJSON_JSONRPC);
        assert_eq!(&sig[1..5], &expected_tag);
    }

    #[test]
    fn decode_mito_tag_round_trips_all_known_protocols() {
        let seed = b"round-trip-test-seed-32-bytes!!";
        for proto in KNOWN_PROTOS {
            let tag = mito_tag(seed, proto);
            let decoded = decode_mito_tag(seed, &tag);
            assert_eq!(
                decoded,
                Some(proto),
                "round-trip failed for 0x{:02X}",
                proto
            );
        }
    }

    #[test]
    fn decode_mito_tag_rejects_wrong_seed() {
        let seed_a = b"seed-alpha-32-bytes-padding!!!!";
        let seed_b = b"seed-bravo-32-bytes-padding!!!!";
        let tag = mito_tag(seed_a, PROTO_NDJSON_JSONRPC);
        assert_eq!(decode_mito_tag(seed_b, &tag), None);
    }

    #[test]
    fn decode_mito_tag_rejects_garbage() {
        let seed = b"test-family-seed-32-bytes!!!!!!!";
        let garbage = [0xFF, 0xFE, 0xFD, 0xFC];
        assert_eq!(decode_mito_tag(seed, &garbage), None);
    }
}
