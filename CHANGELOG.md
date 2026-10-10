# bearDog — Evolution Record

The changelog is sorted by capability surface, not by date.
Each section tells the arc: what emerged, what it replaced, what it became.
The date-sorted history lives in `CHANGELOG_ARCHIVE.md`.

`H(data|epitope) < H(data|date) < H(data)`

---

## BTSP Session Protocol — encrypted wire security

BTSP evolved from NULL-cipher stubs to full multi-phase handshake with bond-type cipher floors, strict UDS enforcement, and riboCipher tier detection.

- **BTSP Phase 3** (Wave 142→150x): ChaCha20-Poly1305 encrypted framing; HKDF-SHA256 session key derivation; `btsp.negotiate` with cipher ranking.
- **Cipher floor enforcement** (Wave 150x): `BEARDOG_BTSP_CIPHER_FLOOR` env rejects ciphers below configured minimum; initial handshake enforces floor, not just re-negotiation.
- **Bond-type cipher awareness** (Wave 150x): `BtspBondType` (Covalent/Ionic) drives per-type floors via `BEARDOG_BTSP_CIPHER_FLOOR_COVALENT/IONIC`.
- **UDS strict mode** (Wave 151a): `BEARDOG_UDS_REQUIRE_BTSP=1` disables `{` bypass on family sockets — all connections must complete BTSP handshake.
- **riboCipher wired** (Wave 150x): `handle_ribocipher_signal` detects `0xEC`/`0xED`/`0xEE` before BTSP fallback on accept loop.
- **Trust issuer exchange** (Wave 131): BTSP trust issuer exchange (P1) — cross-gate session establishment protocol.
- **Backpressure signaling** (Wave 150x): Semaphore saturation returns JSON-RPC `-32003` with `retry_after_ms` instead of indefinite hang.

---

## Genetic Enrollment & Lineage — two-layer DNA verification

Enrollment evolved from simple HMAC proofs to a dual-layer genetic model with seed rotation, replay protection, and nuclear lineage distance.

- **Two-layer genetic model** (Wave 150x): Mitochondrial gate (HMAC/family seed) + optional nuclear lineage distance (trust tier from tree depth).
- **GeneticEnrollmentTier** (Wave 150x): Identity/Kin/Sibling/Extended/Distant tiers with `auto_enroll()` predicate and wire names.
- **Seed rotation via HKDF** (Wave 150x): `enrollment_key(gen) = HKDF-SHA256(FAMILY_SEED, FAMILY_ID, "enrollment-v{gen}")`; grace-period dual verification during rotation.
- **Replay protection** (Wave 150x): Timestamp validity window (±300s) + BLAKE3 digest replay cache (10K entries, self-pruning).
- **enrollment.verify endpoint** (Wave 150u): HMAC-SHA256 proof verification aligned to songBird wire contract; constant-time comparison.
- **BirdSong generation wiring** (Wave 150x): `BirdSongEncryption` tracks `current_generation`; `advance_generation()` for rotation orchestration.
- **Enrollment module split** (Wave 151b): 1061L → 7 modules by concern (handler, crypto, config, lineage, replay_cache).

---

## Cryptography & Key Management — pure Rust sovereign crypto

Crypto evolved from ring-dependent stacks to pure Rust implementations with 109+ IPC methods and throughput benchmarks.

- **Pure Rust crypto milestone** (Wave 145): Ring eliminated from dependency graph; ed25519-dalek, chacha20poly1305, hkdf, sha2 throughout.
- **crypto.hash.blake3** (Wave 150x): Dot-separated semantic alias for songBird crypto delegation; 109 crypto methods registered.
- **Crypto throughput benchmark** (Wave 150u): ChaCha20/AES-GCM/Ed25519/X25519/HKDF/HMAC at 64B–1MB for WireGuard parity assessment.
- **Key management store** (Wave 150u): Clone reduction in signing/symmetric key generation; DPAPI safety documented for Windows FFI.
- **Syn elimination** (Wave 52): Procedural macro dependency removed from hot paths.
- **Quantum crypto feature-gated** (Wave 130): `quantum_crypto` behind feature flag; deprecated modules deleted.

---

## CredentialStore & HSM — platform secret backends

Secret storage evolved from Linux-only stubs to a trait-based multi-platform backend with Android Keystore and iOS StrongBox readiness.

- **CredentialStore trait** (Wave 150t): Platform-dispatch enum — Linux SecretService, Windows DPAPI, Android Keystore, iOS StrongBox stub.
- **Android Keystore backend** (Wave 150u): TEE/StrongBox master key + ChaCha20-Poly1305 file vault; `#[cfg(target_os = "android")]` gated.
- **HSM platform abstraction** (Wave 149b): Universal HSM config with env wiring; operation router timeout/retry from env.
- **Human entropy orchestration** (Wave 151c): `BEARDOG_ENTROPY_COLLECTION_TIMEOUT_MS` wired; Phase 1 shipped per spec audit.
- **HSM discovery ports** (Wave 150x): `BEARDOG_HSM_DISCOVERY_PORTS` replaces hardcoded `[1792, 7000, 9000, 443]`.

---

## Authentication & Token Issuance — ionic bonds and session scopes

Auth evolved from wildcard token minting to scoped issuance with capability.call protection and mesh trust exchange.

- **Token scope restriction** (Wave 151d): `auth.issue_ionic/session` default scope `[]` not `["*"]` — callers must explicitly request scopes.
- **capability.call protected** (Wave 151d): Removed from PUBLIC_METHODS — requires valid auth token to prevent auth bypass on re-dispatch.
- **Ionic bond verification** (Wave 109): Cross-family contract verification with ACME Phase 3 renewal daemon integration.
- **Ionic lease + seed fingerprint** (Wave 102): Tower Atomic glacial debt — lease lifecycle and seed fingerprint validation.
- **Auth event bus** (Wave 139): Decoupled auth lifecycle events from inline handler logic.
- **auth.verify_ionic scopes fix** (Wave 131): Scope validation corrected for ionic bond verification path.

---

## Capability Routing & Mesh Security — who may call what

Routing evolved from hardcoded primal coupling to `capability.call` dispatcher with cross-gate trust seeding and method gate centralization.

- **capability.call dispatcher** (Wave 94): P1 mesh blocker resolved — routes crypto/signing/storage calls to appropriate handlers.
- **Auto trust seeding** (Wave 140): BD-TRUST-01 — `auth.exchange_trust` seeds cross-gate trust without manual ceremony.
- **Cross-gate trust hardening** (Wave 123→135): Covalent mesh security; trust evaluation before accepting mesh connections.
- **MethodGate centralization** (Wave 119): SO_PEERCRED + centralized pre-dispatch gate; public vs protected method classification.
- **Relay interface Phase 3.5** (Wave 138): Seed fingerprint validation on relay messages; Ed25519 relay signatures.
- **Error sanitization** (Wave 151d): Filesystem paths and OS details stripped from JSON-RPC responses; full errors logged server-side.

---

## ACME/TLS Gateway — periplasm HTTPS front

The gateway evolved from hardcoded port stubs to ACME-operational TLS termination with configurable upstream routing.

- **ACME daemon operationalization** (Wave 112): `beardog-acme` crate with renewal daemon; shadow metrics for certificate lifecycle.
- **Tower HTTP gateway** (Wave 132c): ACME TLS front with configurable upstream; `BEARDOG_GATEWAY_UPSTREAM_HOST` env.
- **TLS termination + rate limiting** (Wave 100): H2-10/H2-11 sovereignty — WAN periplasm hardening.
- **ACME Phase 2 crate** (Wave 107): Shadow metrics + JupyterHub design; CSR evolution in Wave 122.
- **Gateway port isolation** (Wave 150u): No hardcoded 7780 — requires explicit `BEARDOG_GATEWAY_UPSTREAM` env (primal isolation).

---

## FIDO2 & Hardware Attestation — hardware-bound identity

Hardware attestation emerged as an IPC surface for UB-2 hardware-authenticated enrollment and ceremony verification.

- **FIDO2/CTAP2 IPC surface** (Wave 103): Hardware-attested authentication methods on JSON-RPC surface.
- **FIDO2 ceremony** (Wave 138b–139b): Full ceremony wire types hardened; attestation field name alignment (Wave 111).
- **Attestation integration** (Wave 110): Self-announcement to biomeOS Neural API with attestation metadata.

---

## Trust Exchange & Mesh Federation — cross-gate identity

Mesh trust evolved from implicit LAN trust to explicit exchange protocols with relay authority and lineage providers.

- **Mesh trust exchange** (Wave 80→140): Cross-gate trust evaluation via security provider; gates verify lineage before mesh connections.
- **Phase 3.5 relay design** (Wave 136): Trust hardening design for relay message verification across subnet boundaries.
- **Lineage proof manager** (Wave 150x): `genetic_distance()` via common ancestor depth; tree-distance trust tiers.
- **Content scope expansion** (Wave 108): `content.*` scope methods for federated content verification.

---

## Architecture & Engineering Discipline — publication-ready security platform

bearDog achieved zero-hardcoding compliance and pen-test readiness through systematic refactoring and spec alignment.

- **Zero hardcoding achieved** (Wave 151c): ZERO_HARDCODING_SPECIFICATION marked ACHIEVED — 0 production violations.
- **Publication pen test** (Wave 151d): 3 CRITICAL findings (error leakage, capability.call bypass, wildcard tokens) — all resolved; 13,974+ tests.
- **File size compliance** (Wave 151b): All production files under 400L; no file exceeds 800L; enrollment/lineage_proof smart-decomposed.
- **Env migration complete** (Wave 128→133): Centralized env keys in `beardog-config`; DNS timeout bug fixed (was mapped to pool size).
- **PerformanceAnalyzer evolution** (Wave 150u): No-op → real statistical analysis with anomaly detection; wired into metrics system.
- **Android compile fixes** (Wave 151d): eastGate readiness — keystore hostname fallback, BTreeMap type corrections.
- **Deep debt audit clean** (Wave 150x): 0 production files >800 LOC; 6 irreducible unsafe (Windows DPAPI); 0 peer-primal hardcoding; ring absent from graph.

---

*Full date-sorted history: `CHANGELOG_ARCHIVE.md`*
*Last compressed: Wave 172*
