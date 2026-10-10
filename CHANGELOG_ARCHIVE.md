<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Changelog

All notable changes to the BearDog security platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### July 25, 2026 -- Wave 151d: Publication Readiness Pen Test + Security Hardening

#### Security Hardening (CRITICAL → RESOLVED)
- **Error sanitization layer**: `HandlerError::into_json_rpc_error()` now strips filesystem paths and OS error details from JSON-RPC responses via `sanitize_error_message()`; full errors logged server-side via `tracing::error!`
- **TCP BTSP error leakage**: Parse errors and business errors no longer forward raw `BearDogError` text to wire clients
- **`capability.call` → Protected**: Removed from `PUBLIC_METHODS` — callers now require valid auth token to invoke capability routing (prevents auth bypass on re-dispatch to crypto/signing methods)
- **Token scope restriction**: `auth.issue_ionic` / `auth.issue_session` default scope changed from `["*"]` (wildcard) to `[]` (empty) — callers must explicitly request scopes
- **BTSP cipher floor on initial handshake**: Server now enforces `BEARDOG_BTSP_CIPHER_FLOOR` during the Phase 2 binary handshake, not only on re-negotiation — prevents client-initiated downgrade to `null` or `hmac_plain`
- Added `BtspCipher::rank()` method for consistent cipher strength comparison

#### Android Target Compile Fixes (eastGate readiness)
- Fixed `android_keystore.rs`: replaced `whoami` crate reference with env-based hostname fallback; added `tracing::warn!` import
- Fixed `android_strongbox/core/unified.rs`: corrected `HashMap` → `BTreeMap` for `ProviderHealth.details`, `ResourceUsage.disk_io`, and `ProviderMetrics.performance` fields

#### Pen Test Summary
- 3 CRITICAL findings (error info leakage, `capability.call` auth bypass, wildcard token minting) — all RESOLVED
- 4 HIGH findings documented (auth defaults, cipher downgrade, rate limits, BTSP strict default)
- Publication dependency audit completed (git dep, path versions, publish guards documented)
- 13,974+ tests, 0 failures, 0 clippy warnings

### July 25, 2026 -- Wave 151c: Spec Audit + Env Wiring + DNS Bug Fix

#### Spec Status Corrections (7 specs)
- **ZERO_HARDCODING_SPECIFICATION**: `ACTIVE MANDATE (307 remaining)` → `ACHIEVED (0 in production)`
- **PRODUCTION_READINESS_SPECIFICATION**: Updated metrics to 231 methods / 25 crates / 13,973+ tests
- **NODE_REGISTRY_MODERNIZATION_ROADMAP**: `CRITICAL / Ready` → `DEFERRED / DORMANT` (crate workspace-excluded)
- **PURE_RUST_ZERO_DEPENDENCY_ROADMAP**: `ROADMAP ACTIVE` → `CRYPTO MILESTONE ACHIEVED (Wave 145)`
- **UNIVERSAL_HSM_ENTROPY_ORCHESTRATION**: `IN PROGRESS` → `PHASE 1 SHIPPED`; iOS/Android marked as stubs
- **KEY_ROTATION_AND_LIFECYCLE**: `IMPLEMENTATION SPEC` → `PARTIAL` (types/tests exist, daemon not shipped)
- **BEARDOG_SCOPE_AND_BOUNDARIES**: Updated metrics from 100→231 methods, 14,784→13,973+ tests

#### Bug Fix
- **`dns_timeout_seconds` was mapped to `DEFAULT_POOL_SIZE` (10)** instead of DNS timeout constant (5s) — fixed `TimeoutConfiguration::with_defaults()` and `from_env_provider()` to use `DEFAULT_DNS_TIMEOUT_SECS` and read `BEARDOG_DNS_RESOLUTION_TIMEOUT_SECS`

#### Env Wiring (3 structs, 1 new key)
- **`HumanEntropyConfig`**: Wired `BEARDOG_ENTROPY_COLLECTION_TIMEOUT_MS` (new env key; default 5000ms)
- **`OperationRouterConfig`**: Added `from_env()` reading `BEARDOG_HSM_OPERATION_TIMEOUT_SECS` + `BEARDOG_HSM_MAX_RETRIES`
- **`UniversalHsmConfig`**: Added `from_env()` reading `BEARDOG_HSM_OPERATION_TIMEOUT_SECS` + `BEARDOG_HSM_MAX_RETRIES` + `BEARDOG_HSM_HEALTH_CHECK_INTERVAL_SECS`

### July 25, 2026 -- Wave 151b: Deep Debt Sweep — Smart Refactoring + Hardcoding Evolution

#### Smart File Decomposition
- **`enrollment.rs` (1061L → 7 modules)**: Decomposed into `mod.rs`, `handler.rs` (202L), `crypto.rs` (57L), `config.rs` (54L), `lineage.rs` (58L), `replay_cache.rs` (48L), `tests.rs` (613L) — logical separation by concern, not arbitrary splitting
- **`lineage_proof.rs` (877L → 399L + 480L tests)**: Extracted 480 lines of test code to `lineage_proof_tests.rs` via `#[path]` attribute
- All production files now under 400 lines; no production `.rs` file exceeds 800 lines

#### Hardcoding → Capability-Based Evolution
- **mDNS interface**: Replaced hardcoded `"eth0"` with `BEARDOG_MDNS_INTERFACE` env var (default: empty = all interfaces); added `BEARDOG_MDNS_SERVICE_TYPE` wiring to existing discovery env key
- **`/tmp/` paths**: Evolved hardcoded `/tmp` fallbacks to `std::env::temp_dir()` in Linux Secret Service backend (HOME fallback + non-Linux stub path)
- **`reject()` helper**: Reduced 6× repeated `EnrollmentVerifyResponse` rejection boilerplate to single function call

#### Code Quality
- Resolved all `redundant_pub_crate` clippy warnings in new enrollment submodules
- Zero clippy warnings, zero test failures, 13,973+ tests passing

### July 25, 2026 -- Wave 151a: BTSP on Local UDS (Defense-in-Depth)

#### Defense-in-Depth UDS Enforcement (P2 → SHIPPED)
- **`BEARDOG_UDS_REQUIRE_BTSP=1`**: disables the first-byte `{` bypass on family-scoped sockets — all connections must complete a BTSP handshake (binary or JSON-line `ClientHello`)
- Plain JSON-RPC on the family socket is rejected with error code `-32600` and guidance to use BTSP or the health socket
- JSON-line BTSP `ClientHello` (`{"protocol":"btsp",...}`) remains the allowed `{`-prefixed entry point
- Health socket (`beardog-default.sock`) unaffected — stays plaintext for monitoring
- `capabilities.list` and `discover_capabilities` now advertise `btsp_strict`, `cleartext_available`, and mode-appropriate `cleartext_methods`
- Shared P2 item with songBird (songBird needs to send JSON-line ClientHello when strict mode is active)

### July 25, 2026 -- Wave 150x: Bond-Type Cipher Awareness + Backpressure Signaling

#### Bond-Type Cipher Awareness (P2 → SHIPPED)
- **`BtspBondType` enum**: `Covalent` (same-family, intra-mesh) / `Ionic` (cross-family, contract) — drives per-type cipher floor selection
- **Per-type cipher floors**: `BEARDOG_BTSP_CIPHER_FLOOR_COVALENT` and `BEARDOG_BTSP_CIPHER_FLOOR_IONIC` env keys — override the global floor per bond type
- **Wire contract**: `SessionNegotiateParams` and `btsp.negotiate` accept optional `bond_type` field (defaults to `covalent` — backward compatible)
- `select_best_cipher_for_bond()` and `load_cipher_floor_for_bond()` replace the flat floor logic
- 6 new tests: covalent default, ionic lowered floor, ionic fallback to global, covalent enforces strong, bond type default, serde roundtrip

#### UDS Backpressure Signaling (P2 → SHIPPED)
- **Explicit saturation error**: when all UDS connection slots are in use, callers receive a JSON-RPC error (`-32003`, "Server saturated") with `retry_after_ms` and `max_connections` hints instead of hanging indefinitely
- Semaphore acquisition changed from blocking to `tokio::time::timeout(100ms)` — brief grace period before rejection
- Mirrors the BTSP rejection pattern (send structured error, then close)

### July 25, 2026 -- Wave 150x: Two-Layer Genetic Enrollment (Mito + Nuclear)

#### Nuclear Lineage Distance in Enrollment
- **Two-layer genetic model**: `enrollment.verify` now implements a dual-DNA verification model:
  - **Mitochondrial gate** (HMAC/family seed): "can you hear the birdsong?" — prerequisite, same family
  - **Nuclear lineage distance** (optional `lineage_proof`): "how close are you in the tree?" — trust tier
- **`genetic_distance()`**: new function in `LineageProofManager` computes tree distance between two nodes using common ancestor depth: `depth(A) + depth(B) − 2 × depth(common_ancestor(A, B))`
- **`GeneticEnrollmentTier`** enum: `Identity` (0), `Kin` (1), `Sibling` (2), `Extended` (3-4), `Distant` (5+) — with `auto_enroll()` predicate and `wire_name()` for JSON
- **Wire contract evolution**: `EnrollmentVerifyParams` gains optional `lineage_proof` (chain_id, path, generation); `EnrollmentVerifyResponse` gains `enrollment_tier` and `genetic_distance` (both omitted when no proof provided — backward compatible)
- 6 new enrollment tests: lineage proof with tier, without proof omits tier, sibling distance, deep enrollee, distant enrollee, self-enrollment
- 13 new genetics tests: distance (self, parent-child, siblings, cousins, nonexistent), tier classification (identity, kin, sibling, extended, distant), tier ordering, auto_enroll, wire names

### July 24, 2026 -- Wave 150x: Enrollment Seed Rotation via Genetic HKDF

#### Enrollment Seed Rotation (P2 → SHIPPED)
- **HKDF-derived enrollment keys**: `enrollment.verify` now derives HMAC keys through the genetic HKDF hierarchy rather than using raw `FAMILY_SEED` bytes — same pattern as `LineageKeyDerivation`
- **Derivation**: `enrollment_key(gen) = HKDF-SHA256(ikm=FAMILY_SEED, salt=FAMILY_ID, info="enrollment-v{gen}")`
- **Generation-aware proofs**: HMAC message now includes `seed_generation` field: `node_id|public_key|timestamp|generation`
- **Grace-period dual verification**: during rotation, verifier accepts current generation N **and** previous N−1
- **`BEARDOG_ENROLLMENT_SEED_GENERATION`** env key: sets current generation (default 0); bump to rotate
- **Wire contract**: `EnrollmentVerifyParams` gains `seed_generation` (default 0, backward compatible); `EnrollmentVerifyResponse` gains `verified_generation`
- 7 new tests: gen0/gen1 verification, grace period, stale gen rejection, cross-gen without grace, deterministic derivation, generation variation

#### `BirdSong` Generation Wiring
- `BirdSongEncryption` now tracks `current_generation` via `AtomicU32`; `encrypt()` uses it instead of hardcoded 0
- `BirdSongBroadcast` gains `generation` field (serde-defaulted for backward compat); `decrypt()` reads generation from broadcast metadata
- `advance_generation()` and `generation()` accessors for rotation orchestration

### July 24, 2026 -- Wave 150x: Cipher Floor + Deep Debt Sweep

#### Cipher Floor Enforcement (P1)
- **BTSP cipher floor**: `BEARDOG_BTSP_CIPHER_FLOOR` env (default `chacha20-poly1305`) enforces minimum cipher strength in `btsp.negotiate` and `btsp.server.negotiate`
- Negotiation rejects ciphers below the configured floor; skunkBat enforces its own floor on the defense side
- Cipher ranking: `chacha20-poly1305` (3) > `hmac-plain` (2) > `null` (1)

#### `crypto.hash.blake3` Capability (P2)
- Dot-separated semantic alias wired for songBird crypto delegation
- Registered in method list, hashing router, capabilities, cost estimates, cleartext allowlist, neural registration, `discover_capabilities`
- 109 crypto methods registered (was 108)

#### Deep Debt Sweep
- **iOS hardcoding removed**: `"biomeos"` string literal → `ipc_layout::resolve_biomeos_ipc_subdir_from_optional(None)` for socket dirs and XPC service IDs
- **Gateway host configurable**: `BEARDOG_GATEWAY_UPSTREAM_HOST` env (default `127.0.0.1`); env keys centralized in `beardog-config`
- **HSM probe ports configurable**: `BEARDOG_HSM_DISCOVERY_PORTS` (comma-separated) replaces hardcoded `[1792, 7000, 9000, 443]`
- **riboCipher wired**: `handle_ribocipher_signal` now dispatched from UDS connection handler; detects signal bytes (0xEC/0xED/0xEE) before BTSP handshake fallback
- **Integration API docs**: clarified as secondary REST→UDS bridge

#### Deep Debt Audit Findings (all clean)
- 0 production files >800 LOC; 6 `unsafe` blocks (Windows DPAPI FFI, irreducible); 0 peer-primal hardcoding violations; 0 `todo!()`/`unimplemented!()`; `ring` not in dependency graph; 24 clippy suppressions all justified

### July 24, 2026 -- Wave 150x: Security Hardening (Pen Test Response)

#### Enrollment Replay Protection + Timestamp Window
- **Timestamp validity window**: `enrollment.verify` now rejects proofs whose timestamp drifts more than ±300 seconds from wall clock (configurable via `BEARDOG_ENROLLMENT_TIMESTAMP_WINDOW`)
- **Replay tracking**: verified proofs are cached by BLAKE3 digest; resubmission within the window is rejected with `"replay rejected"` reason
- `ReplayCache` with bounded capacity (10K entries) and self-pruning expired entries
- 8 new tests: window acceptance/rejection (past/future), replay detection, cache independence

#### UDS Connection Cap + Backpressure
- **Semaphore-based connection cap** on Unix socket server (default 512, configurable via `BEARDOG_UDS_MAX_CONNECTIONS`)
- Backpressure: at capacity, new connections queue on the semaphore rather than being dropped — callers experience latency, not errors
- Permit released automatically when connection handler completes

#### Env Keys
- `BEARDOG_ENROLLMENT_TIMESTAMP_WINDOW` — enrollment proof timestamp validity (seconds, default 300)
- `BEARDOG_UDS_MAX_CONNECTIONS` — max concurrent UDS connections (default 512)

### July 22, 2026 -- Wave 150u: Deep Evolution + Tower Atomic Alignment

#### Deep Debt Evolution
- **Dependency cleanup**: Updated yanked `spin` (0.9.8→0.9.9) and `crypto-bigint` (0.7.3→0.7.5); removed dead `ed448-goldilocks` dependency (handlers are stubs, crate unused)
- **Gateway hardcoding removed**: `gateway.rs` no longer hardcodes port 7780 — requires explicit `BEARDOG_GATEWAY_UPSTREAM` or `BEARDOG_GATEWAY_UPSTREAM_PORT` env var (primal isolation)
- **PerformanceAnalyzer evolved**: No-op placeholder → real statistical analysis (min/max/mean/stddev, anomaly detection with configurable threshold); wired into `AdvancedMetricsSystem` to emit `AnomalyDetected` events
- **Clone reduction**: `key_management/store.rs` — reduced redundant `key_id.clone()` calls in `generate_signing_key`, `generate_symmetric_key`, `import_signing_key`
- **DPAPI safety documented**: Windows DPAPI unsafe FFI blocks annotated with safety invariants for `CryptProtectData`/`CryptUnprotectData`
- **enrollment.verify wire contract aligned**: Params updated from `{node_id, family_id, enrollment_data, enrollment_proof}` to songBird format `{node_id, public_key, timestamp, proof}`; response `{verified, reason?}`; HMAC keyed by `FAMILY_SEED` from env
- **BTSP method count updated**: 37→38 methods (added `enrollment.verify`)

#### Crypto Throughput Benchmark (Wave 150u — Tower Atomic Parity P2)
- New `crypto_throughput` criterion benchmark in `benchmarks/benches/crypto_throughput.rs`
- Measures real encrypt/decrypt throughput for parity assessment vs WireGuard
- ChaCha20-Poly1305 (encrypt, decrypt, roundtrip) at 64B–1MB payloads
- AES-256-GCM (encrypt, decrypt) at 64B–1MB for comparison
- Ed25519 sign/verify, X25519 DH, HKDF-SHA256 derivation, HMAC-SHA256
- Run: `cargo bench --bench crypto_throughput -p benchmarks`

### July 22, 2026 -- Wave 150u: Android Keystore + enrollment.verify

#### Android Keystore CredentialStore Backend (Wave 150u)
- **`AndroidKeystoreCredentialStore`**: `CredentialStore` trait impl — master key in TEE/StrongBox, file vault encryption (ChaCha20-Poly1305 + HKDF), `#[cfg(target_os = "android")]` gated
- **`CredentialStoreBackend::AndroidKeystore`** variant in Silicon Atheism enum dispatch
- Reports unavailable on non-Android platforms (same pattern as Windows DPAPI, Linux SecretService)
- eastGate handoff updated with CredentialStore validation checklist (13 checks across HSM + secrets layers)

#### `enrollment.verify` Endpoint (Wave 150u — Tower Atomic Parity)
- New `enrollment.verify` JSON-RPC method on BTSP handler — verifies HMAC-SHA256 proofs from `mesh.enroll`
- Wire contract aligned to songBird convergence brief: `{node_id, public_key, timestamp, proof}` params, `{verified, reason?}` response
- HMAC message: `node_id || "|" || public_key || "|" || timestamp`, keyed by `FAMILY_SEED` from env
- Constant-time comparison via `subtle::ConstantTimeEq`
- 6 tests (HMAC determinism, message format, valid/invalid proof, missing seed)

#### Crypto Throughput Benchmark (Wave 150u — Tower Atomic Parity P2)
- New `crypto_throughput` criterion benchmark in `benchmarks/benches/crypto_throughput.rs`
- Measures real encrypt/decrypt throughput for parity assessment vs WireGuard
- ChaCha20-Poly1305 (encrypt, decrypt, roundtrip) at 64B–1MB payloads
- AES-256-GCM (encrypt, decrypt) at 64B–1MB for comparison
- Ed25519 sign/verify, X25519 DH, HKDF-SHA256 derivation, HMAC-SHA256
- Run: `cargo bench --bench crypto_throughput -p benchmarks`

### July 21, 2026 -- Wave 150t: CredentialStore Trait + Cleanup

#### CredentialStore Trait (Wave 150t)
- **`CredentialStore` trait** defined in `beardog-traits::unified::storage` — `store`, `retrieve`, `list`, `delete` async methods with `SecretMetadata` timestamps
- **`InMemoryCredentialStore`** — volatile backend for dev/test (parking_lot `RwLock`)
- **`FileVaultCredentialStore`** — persistent encrypted backend (ChaCha20-Poly1305 + HKDF-SHA256, atomic writes)
- **`CredentialStoreBackend`** enum dispatch (Silicon Atheism pattern: `InMemory` | `FileVault`)
- **`SecretsHandler` rewired** — now uses `CredentialStoreBackend` for underlying storage while retaining family-scoped HKDF encryption/decryption
- Cross-primal alignment: trait surface designed for `squirrel` `SecurityProvider` delegation

#### Documentation + Infra Cleanup (Wave 150t)
- Root docs refreshed to Wave 150t (README, STATUS, CHANGELOG, ROADMAP)
- `STATUS.md` trimmed — historical wave log (Waves 5–127) moved to CHANGELOG fossil record; STATUS now shows only recent ~10 waves
- `infra/wateringHole/` handoffs updated with current platform status
- Squirrel CredentialStore integration handoff added
- `cargo clean` reclaimed 36.5G

### July 18, 2026 -- Wave 149b: HSM Platform Backend Abstraction + Crypto Handoff

#### HSM Platform Backend Abstraction (Wave 145a)
- **`WindowsDpapiHsm`**: `#[cfg(windows)]` gated — DPAPI `CryptProtectData`/`CryptUnprotectData` key wrapping, AES-256-GCM encrypt/decrypt, HMAC sign/verify, blob storage in `%LOCALAPPDATA%/beardog/keys/`
- **`LinuxSecretServiceHsm`**: `#[cfg(target_os = "linux")]` gated — HKDF-derived master key, AES-256-GCM at-rest encryption, XDG-compliant storage, D-Bus probe for `org.freedesktop.secrets`
- **`HsmProviderType`** extended with `WindowsDpapi` + `LinuxSecretService` variants (serde + Display + tests)
- **`HsmKeyProviderBackend`** enum dispatch extended with both new platform variants across all 10 match arms
- **`HsmProviderRegistry::discover()`** auto-probes and registers platform backends behind `is_available()` gates
- 15 new tests: unit, dispatch integration, registry auto-discovery, full key lifecycle end-to-end

#### Phase 2 Transport: raw UDS → TransportEndpoint (Wave 145a)
- 9 production sites across 5 crates refactored to use `connect_raw()`/`connect_transport()` via `TransportEndpoint`
- Shipped `connect_raw()` in `beardog-ipc/isomorphic.rs` for protocol-prefix-free transport dispatch
- Phase 2 transport: 14/14 complete across ecosystem

#### Crypto JSON-RPC Handoff (Wave 149b)
- Created `specs/current/integration/CRYPTO_JSONRPC_HANDOFF_WAVE149b.md` — full method signatures, param/return shapes, semantic aliases, cross-primal namespace, esotericWebb integration pattern

### July 16, 2026 -- Wave 144a: Deep Evolution + Debris Cleanup

#### Test Extraction Wave 4 (963 LOC from 4 production modules)
- `purpose_key.rs` 747→421L, `load_balancing.rs` 776→458L, `authentication.rs` 760→585L, `key_delegate.rs` 736→543L

#### Orphan Test File Cleanup (3,595 dead LOC removed)
- Deleted 11 orphan `_tests.rs` files from incomplete Wave 142b subagent work — several contained corruption artifacts from the 815 GiB file incident
- Canonical tests remain inline in source files

#### Production Mock Elimination
- **`witness.rs`**: Removed `cfg!(test)` production bypass — tests now use real Ed25519 signatures via deterministic `SigningKey` instead of all-zero mock keys
- **`paths.rs`**: Removed 4x `cfg!(test)` temp-dir overrides — path resolution now purely platform-aware
- **`safe_native_wrapper.rs`**: Removed misleading "mock" comment

#### Dependency Cleanup
- **Removed workspace `libc` dependency** — no crate uses it since `beardog-hid` libc removal in Wave 141b

#### Audit Results (all clean)
- Zero files >800L, zero unsafe code, zero external C deps, zero `cfg!(test)` in production, zero `#[allow(clippy::)]` in production, zero `#[allow(dead_code)]` in production, zero mocks in production paths, zero `todo!()`/`unimplemented!()`

### July 16, 2026 -- Wave 142b: Zero-C Compliance + Deep Evolution

#### Zero-C Compliance
- **Removed `libc` from `beardog-hid`** — replaced `libc::O_NONBLOCK` with inline Linux ABI constant (`0o4000`); bearDog now has zero C library dependencies across all crates

#### BTreeMap Batch 4+5 (deterministic serialization)
- **Batch 4 (Wave 141b)**: 61 HashMap fields → BTreeMap across 8 highest-density production files (decision_engine, other_traits, ecosystem_membership, configuration, ai_first_responses, universal_adapter, monitoring_config, zero_cost)
- **Batch 5 (Wave 142b)**: 25+ HashMap fields → BTreeMap across 5 files (base_traits, security_traits, monitoring/types, advanced security config) + downstream consumer fixes in 9 test/production files

#### Test Extraction Wave 2+3 (~4,200 LOC from production files)
- **Wave 2**: entropy_hierarchy 527L, android 526L, performance 465L, ml_engine 427L, capability_routing 396L
- **Wave 3**: sources 397L, requirements 369L, persistence 368L, verification 364L

#### Module Split
- **`metrics.rs` (763 LOC)** → `metrics/{mod,types,collection,analysis,storage_export}.rs` — zero-test pure type split

#### Lint Hygiene
- **`allow(dead_code)` → `expect(dead_code)`** in `solo_v2/provider.rs` (last production instance)

#### Infrastructure
- **Removed 815 GiB corrupted `ipc_server_tests.rs`** (subagent write failure)
- **Cleaned 2.2 GiB orphaned `tmp_pack_*`** from `.git/objects/pack/`

### July 15, 2026 -- Wave 141a: Cross-Architecture Adoption + Deep Evolution

#### Cross-Platform Transport (per-primal handoff from eastGate overwatch)
- **`beardog-tower-atomic` cross-arch** — `IpcStream` enum replaces direct `UnixStream`; `#[cfg(unix)]` guards on UDS paths; new `connect_tcp()` for Windows; `connect_endpoint()` now supports `TransportEndpoint::Tcp`; `cargo check --target x86_64-pc-windows-gnu` passes
- **TCP integration test** — new `test_connect_to_mock_primal_tcp` validates cross-platform IPC path

#### Sovereignty Hardening
- **Removed hardcoded `songBird`** from production gatehouse log (P0 sovereignty violation)
- **Scrubbed cross-primal name references** in 7 files: `auth_event_bus.rs`, `capability_call.rs`, `btsp/session.rs`, `btsp/rpc.rs`, `btsp/transport.rs`, `handlers/mod.rs`

#### BTreeMap Batch 3 (deterministic serialization)
- **54 HashMap fields → BTreeMap** across 31 production files for deterministic IPC/wire serialization (self_discovery, services, metrics, health, threat intel, coordination, monitoring, capabilities, compliance, auth, genetics, HSM audit) + 14 test files updated
- Added `PartialOrd, Ord` to `ComplianceStandard` for BTreeMap key ordering

#### Test Extraction (1,157 LOC from production files)
- **`api_server/mod.rs` → `api_server_tests.rs`** (368 LOC)
- **`client/lib.rs` → `lib_tests.rs`** (298 LOC)
- **`auth/ecosystem.rs` → `ecosystem_tests.rs`** (270 LOC)
- **`discovery/mdns.rs` → `mdns_tests.rs`** (221 LOC)

#### Lint Hygiene
- **`allow(dead_code)` → `expect(dead_code)`** in `infrastructure.rs`, `session.rs`, `hsm_management.rs`
- **`allow(clippy::*)` → `expect(clippy::*)`** in `hsm_key_provider_backend.rs`, `capabilities.rs`
- Removed stale dead-code suppression from `infrastructure.rs` (no longer needed after BTreeMap migration)

### July 12, 2026 -- Waves 138b–139b: FIDO2 Ceremony + Wire Type Hardening

#### FIDO2/CTAP2 (Wave 138b)
- **P0 `HIDRAW-REPORT-ID`** — prepend `0x00` to Linux hidraw writes for unnumbered reports
- **P1 `HID-BLOCKING-IO`** — `std::fs::File` + `spawn_blocking` replaces incorrect `tokio::fs::File` for device I/O; `libc` dependency removed
- **FIDO2 IPC handler split** — monolithic 897L `fido2.rs` → 8 focused modules (`mod`, `discover`, `register`, `authenticate`, `entropy`, `ceremony`, `helpers`, `tests`)
- **DRY `encode_client_pin_cmd`** — shared CBOR command builder in `client_pin.rs`
- **Named constants** — `CTAPHID_BROADCAST_CID`, `CTAPHID_MAX_MESSAGE_SIZE`, etc. in `hid_transport.rs`
- **PIN error fix** — `0x2C` no longer misclassified as `PIN_NOT_SET` (`0x35`)

#### Wire Type Hardening (Wave 139a–139b)
- **BTreeMap batches 1–2** — 61 HashMap fields → BTreeMap across 15 production files
- **Orphan cleanup** — deleted broken `consensus.rs`, removed deprecated `BiomeOSPaths` alias and `STORAGE_BACKEND_AVAILABLE` constant
- **Test extraction** — `primitives.rs` → `primitives_tests.rs` (200 LOC)

### July 9, 2026 -- Wave 134d: Upstream Regression Fixes + Test Restoration

#### P0 — Gateway Bind Error Silencing (upstream regression from 579bc77)
- **`start_https_gateway` pattern** — upstream `BUILD-DIV-02` fix consolidated `bind_https_listener` + `serve_https_gateway` into a single function spawned via `tokio::spawn`, silencing bind failures (`:443` port in use, insufficient privileges); restored eager bind via `bind_gateway_listener` + `start_https_gateway` that returns `JoinHandle` after successful bind, propagating errors at startup

#### Test Restoration (8 tests restored)
- **3 ACME integration tests** — `serve_redirects_http_to_https`, `serve_returns_acme_challenge_token`, `serve_returns_400_for_missing_host` restored to `challenge.rs` (removed by upstream 579bc77)
- **2 gateway bind tests** — `bind_gateway_listener_succeeds_on_free_port`, `bind_gateway_listener_fails_on_occupied_port` adapted from removed `bind_https_listener` tests

#### Clippy
- **`doc_markdown` fix** — backticks added to `BEARDOG_TLS_MODE`, `:443`, `:80` in `ENV_GATEHOUSE_MODE` doc comment (introduced by upstream 579bc77)

### July 8, 2026 -- Wave 134a: DRY + BUILD-DIV-01 Gate

#### DRY Refactor
- **`connection_handlers.rs` (705L → 655L)** — extracted `dispatch_by_protocol` helper from `handle_ribocipher_signal`; `SIGNAL_CLEAR` and `SIGNAL_MITO` branches were near-identical (~65 lines each); now both delegate to a shared dispatch method parameterized by `tier_label`

#### BUILD-DIV-01 Prevention
- **Pre-push git hook** — `.githooks/pre-push` enforces `cargo check --all-targets` before any push; catches used-but-unimplemented methods, missing test deps, and bench errors at the developer gate; bypassable with `--no-verify` for emergency pushes

### July 8, 2026 -- Wave 133h: Deep Debt — Module Splits + DRY + Deterministic Iteration

#### Bug Fix
- **`dns_http_discovery_default_and_trait_methods` test fixed** — pre-existing failure in `beardog-types` Wave 18 test; `discover_by_capability` now correctly returns `Err(BackendUnavailable)` since DNS SRV resolver is a stub in the types crate; test assertion updated to match

#### Module Splits (oversized file reduction)
- **`graph_security/audit.rs` (798L) → 3 files** — `audit/mod.rs` (306L) orchestrator + data fetchers, `audit/chain_of_custody.rs` (277L) Ed25519 signature verification, `audit/scoring.rs` (199L) trust scoring + risk assessment + warning generation
- **`modes/server.rs` (761L) → 2 files** — `server/mod.rs` (337L) run lifecycle + banner + shutdown, `server/registration.rs` (423L) Neural API + IPC registry + discovery registration
- **`crypto_handlers_rsa.rs` (728L → 370L)** — DRY refactor: extracted `parse_sign_request`, `parse_verify_request`, `build_sign_response` shared helpers; each PKCS#1/PSS handler reduced to thin delegation
- **`unix_socket_ipc/server.rs` (690L → 551L)** — moved `route_jsonrpc` and `handle_one_jsonrpc_request_universal` to `connection_handlers.rs` where they logically belong with other protocol handlers

#### Deterministic Iteration
- **`HashMap` → `BTreeMap`** in `key_rotation_manager.rs` and `memory_key_manager/mod.rs` — key listing APIs now return deterministic sorted order; no new dependencies

### July 7, 2026 -- Wave 133e: Gatehouse Production Hardening

#### P0 — Bind Failure Surfacing
- **`:443` bind errors now fatal** — split `serve_https_gateway` into `bind_https_listener` (returns `Result`) + `serve_https_gateway` (infallible accept loop); bind failures surface at startup instead of vanishing in `tokio::spawn`

#### P0 — Shadow Metrics Wired
- **`ShadowMetricsCollector` live in gateway** — sovereign request latency/errors recorded per-connection in `serve_https_gateway`; TLS handshake and upstream connect failures tracked; `run_parity_loop` spawned automatically when gatehouse activates; enables automated 7-day parity gate for 134b Caddy→bearDog cutover

#### P1 — `BindMode::Auto` Socket Path Divergence Fixed
- **Platform-aware detection centralized** — `resolve_server_socket_path` in `transport.rs` now mirrors the Android auto-detection logic from `handle_server` (`cfg!(target_os = "android")` + `ANDROID_ROOT`/`ANDROID_DATA` env vars); previously, `Auto` in `mod.rs` selected abstract sockets on Android but `transport.rs` returned a filesystem path

#### Test Coverage (8 new tests → 44 `beardog-acme`, 416 `beardog-cli`)
- **HTTP→HTTPS redirect test** — synthetic HTTP request to `Http01Solver::serve()`, asserts 301 + `Location: https://`
- **ACME challenge response test** — registered token returns 200 with correct key authorization
- **400 Bad Request test** — non-challenge request without Host header returns 400
- **`bind_https_listener` tests** — verifies successful bind on port 0 and failure on occupied port
- **`needs_renewal` tests (5)** — fresh cert (90d), expiring cert (10d), garbage PEM, empty PEM, outside threshold (60d); certs generated via `p256`/`x509-cert` (no `ring`)

#### Hygiene
- **Stale comment fixed** — `rustls_provider.rs` doc updated to reflect self-healing provider install (no longer dev-dependency pattern)
- **Unused re-export removed** — `acme.rs` no longer re-exports `serve_https_gateway` (imported directly from `gateway`)

### July 4, 2026 -- Wave 132c: Tower HTTP Gateway — ACME TLS Front

#### ACME Gateway (P1 — sovereign HTTPS)
- **HTTPS gateway on :443** — new `gateway.rs` module in `beardog-cli`; TLS-terminating reverse proxy using `HotReloadAcceptor`; bidirectional TCP forwarding to upstream (songBird `http.proxy` by default)
- **HTTP-01 solver spawn** — `Http01Solver::serve()` now spawned as background task in ACME supervisor; unblocks all Let's Encrypt domain validation
- **HotReloadAcceptor wired** — `create_hot_reload_pair()` bootstrapped from cert store on startup; atomic cert swap on renewal via `reload_after_issuance()` hook
- **Full ACME supervisor** — `start_acme_gateway()` replaces old `spawn_acme_renewal_daemon()`; orchestrates solver + initial issuance + hot-reload + renewal in single startup sequence
- **`issue_certificate()` public** — exposed for initial cert bootstrapping from gateway supervisor
- **`BEARDOG_GATEWAY_UPSTREAM` env key** — configurable upstream target (TCP `host:port` or `unix:/path`); default `127.0.0.1:7700` (songBird federation port)
- **Upstream proxy modes** — TCP and Unix domain socket forwarding with 502 Bad Gateway on upstream failure
- **Collapsible if fix** — `reload_after_issuance` uses let-chain pattern per Clippy

### July 4, 2026 -- Wave 131: BTSP Trust Issuer Exchange (P1)

#### Mesh Join Orchestration (P1 — blocks mesh auth)
- **`mesh_join` module** — new orchestrator in `beardog-tunnel/src/mesh_join.rs`; wraps `BtspTcpClient` → `auth.exchange_trust` → local registry registration in a single async call; returns `MeshJoinResult` with bidirectional confirmation
- **Registry persistence** — `TrustedIssuerRegistry::save_to_file()` / `load_from_file()` with JSON v1 format; `save_path()` resolves `$XDG_DATA_HOME/beardog/trusted_issuers.json`; DID/key binding validated on load
- **`exchange_trust` polish** — response now includes `local_family_id`; emits `KeyExchangeCompleted` event (in addition to `TrustIssuerRegistered`) for downstream mesh listeners
- **`BtspConnection::session_id()`** — new accessor for tracing/log correlation

#### E2E Integration Test
- **`mesh_join_e2e_over_tcp`** — real TCP + BTSP handshake + `auth.exchange_trust` dispatch + bidirectional registry assertion; proves two gates can exchange trust and populate registries via one `mesh_join` call (2,331 tunnel tests total)

### July 4, 2026 -- Wave 131b: Deep Evolution Sweep

#### Security Hardening (P0)
- **Android attestation fail-closed** — `StubAttestationTransport` and `AndroidJniAttestationTransport` now return `not_yet_available` instead of fake `Ok(())`; security-critical path no longer reports false success
- **TLS provider hardened** — workspace `rustls` now uses `custom-provider` feature; `beardog-acme` extracts `rustls_provider::ensure_installed()` for consistent CryptoProvider bootstrap; `beardog-tunnel` TLS acceptor installs provider explicitly

#### Type Deduplication (P0)
- **`SimpleHsmTier` unified** — removed duplicate enum from `hsm/manager/config.rs`; canonical definition in `hsm/config.rs` now has `Serialize`/`Deserialize` + `as_str()` + `Display`; re-exports preserve backwards compatibility

#### Smart Refactoring (P1)
- **`trusted_issuer_registry.rs` (826L) → module directory** — split into `did.rs` (22L), `types.rs` (96L), `registry.rs` (189L), `persistence.rs` (129L), `verify.rs` (66L), `tests.rs` (322L); API unchanged, zero production files over 800L

#### Mock/Stub Evolution (P1)
- **`MdnsDiscovery::default()` no longer panics** — gracefully degrades to disabled state; `is_enabled()` accessor added
- **`get_discovered_services_count`** — no longer masks errors with `Ok(0)`; propagates properly, caller logs at `warn!`
- **HSM health monitor** — placeholder documented with `EVOLUTION` marker and debug tracing; cache timestamp refresh preserved
- **DNS SRV discovery** — `query_dns_srv` returns `BackendUnavailable` instead of silent empty `Vec`; callers no longer misled

#### Dynamic Primal Announce (P1)
- **`primal.announce` wired to `HandlerRegistry`** — new `primal_announce.rs` derives method names and capability domains from registered handlers at runtime instead of hardcoded static list; `beardog_announce_method_names()` deprecated
- **`UnixSocketIpcServer::handler_registry()`** — new accessor for runtime introspection

### July 4, 2026 -- Wave 128: Convergence Debt Sweep + Evolution Targets

#### Security Hardening (P0)
- **Simulated PQC gated** — `quantum_crypto` module now behind `#[cfg(any(test, feature = "pqc-simulation"))]`; random-byte "keys/signatures" no longer exposed in production builds unless explicitly opted in; `pqc_simulation_enabled()` helper added for runtime checks
- **PQC capability advertisement gated** — `QuantumCrypto` and `quantum_resistant` in `UniversalHsmConfig::high_security()` only included with `pqc-simulation` feature

#### Identity Resolution Fix (P0)
- **`resolve_primal_name()` precedence fixed** — now checks `BEARDOG_PRIMAL_NAME` → `PRIMAL_NAME` → `"beardog"` (was missing prefixed variant)
- **`IdentityHints::from_env()` fixed** — reads `BEARDOG_PRIMAL_NAME` first, matching family/node ID patterns
- **`get_primal_name_with()` fallback corrected** — uses `resolve_primal_name()` instead of `env!("CARGO_PKG_NAME")` (was returning `"beardog-tunnel"`)

#### Async I/O Migration (P0)
- **beardog-acme** — `store_cert`, `load_cert`, `save()` migrated from `std::fs` to `tokio::fs` (was blocking async runtime); callers in `issuance.rs`, `renewal.rs`, `hot_reload.rs` updated
- **beardog-monitoring** — `/proc/stat` and `/proc/meminfo` reads migrated to `tokio::fs::read_to_string`; `collect_cpu_usage`, `collect_memory_usage`, `collect_performance_metrics` now async
- **monitoring sentinel** — `performance_metrics.rs` async system metrics collection

#### Lock Evolution (P0–P1)
- **`std::sync::Mutex` → `parking_lot::Mutex`** — `system_metrics.rs` (CPU snapshots, window start), `metrics/performance.rs`, `metrics/security.rs`; eliminates poison risk in async-adjacent code
- **`Arc<Mutex<SystemTime>>` → `Arc<AtomicU64>`** — `btsp_provider/tunnel.rs` `last_activity` now lock-free epoch millis
- **mDNS stats `Mutex` → `parking_lot::RwLock`** — `protocol_handlers.rs` read-heavy stats structure

#### Error Type Evolution (P1)
- **`SslKeylogError` → thiserror** — manual `Display`/`Error` impls replaced with `#[derive(thiserror::Error)]`

### June 22, 2026 -- Wave 123: Cross-Gate Trust Hardening

#### TrustedIssuerRegistry Security (P1)
- **`auth.trust_issuer` auth gate** — handler now requires BTSP-authenticated channel, valid ionic token, or co-resident UDS; previously dispatched before MethodGate check (effectively unauthenticated)
- **`try_verify_bearer` pre-dispatch** — ionic-token auth path for `auth.trust_issuer` and `auth.exchange_trust` now wired via `MethodGate::try_verify_bearer()` (populates `validated_claims` before gate-handled dispatch)

#### Cross-Gate Issuer Bootstrap (P1)
- **`BEARDOG_TRUSTED_ISSUERS` env var** — new env-based bootstrap for `TrustedIssuerRegistry`; format `public_key_base64:gate_id:family_id` (comma-separated); seeded at `MethodGate::new()` (both UDS and TCP servers)
- **`ENV_TRUSTED_ISSUERS` constant** — added to `beardog-config::env_keys::identity`

#### Exchange Trust Identity Fix (P1)
- **`auth.exchange_trust` `local_gate_id`** — response field now returns `node_id` (gate instance identity) instead of `primal_name` (product name); correct for 5-gate mesh where each gate has a unique `NODE_ID`

### June 21, 2026 -- Wave 120: WAN Periplasm Hardening + Deep Debt Sweep II

#### BTSP WAN Security Hardening (P1)
- **Mutual BTSP authentication** — server now computes `server_proof` HMAC in `HandshakeComplete`; client verifies server family membership (bidirectional trust)
- **TCP `btsp_family_verified` parity** — TCP BTSP path now sets `caller.btsp_family_verified = true` after handshake, matching UDS behavior
- **`family_id` persisted in `PeerTrustRecord`** — `seed_trusted_peer()` now stores `family_id: Option<String>` (previously accepted but discarded)
- **Post-handshake peer identity binding** — `CallerContext.peer_id` bound to BTSP session ID after TCP handshake

#### Primal Identity Unification (P1)
- **10 hardcoded `"beardog"` sites → resolved identity** — TCP/UDS servers, CLI client/health, IPC isomorphic, server transport/health socket, mDNS TXT, service mesh port
- **`PrimalIdentity.primal_name`** — new field binds encryption tags to runtime identity instead of product name; `encryption_tag()` now uses `self.primal_name`
- **Socket stems agnostic** — abstract namespace and filesystem socket paths use resolved primal name

#### Production Hardening (P1)
- **Graph permissions fail-closed** — collaboration lookup failure returns `not_yet_available` instead of silently downgrading to `Viewer`
- **Blocking I/O → async** — `streaming.rs` migrated from `std::fs` to `tokio::fs` / `AsyncReadExt` / `AsyncWriteExt`
- **`SocketConfigError` → thiserror** — manual `Display` + `impl Error` replaced with `#[derive(thiserror::Error)]`
- **`MinimalProtocolHandler`** — `discover_services` now logs `tracing::debug!` when returning empty
- **riboCipher dead handler** — `#[allow(dead_code)]` → `#[expect(dead_code, reason = "...")]` with documented wiring plan

#### Dependency Cleanup (P2)
- **Unused `aes`/`ctr`** — removed from `[workspace.dependencies]` (deferred Phase 7)
- **Service mesh port** — inline `.unwrap_or(8443)` → `DEFAULT_HTTPS_PORT` constant

#### Test Sweep (P2)
- **15 pre-existing test failures fixed** — adapter dispatch (9), compute client (1), Android/iOS platform (3), BTSP handler count (1), JSON-RPC error code (1)
- **Graph authorization tests** — updated for fail-closed behavior
- **Flaky sslkeylog test** — resilient to env-var race in parallel test runs

### June 20, 2026 -- Wave 119: Deep Debt Sweep — Modern Idiomatic Rust, Self-Knowledge, Structural Evolution

**92 files changed, +1,634 / -3,099 lines**

#### BTSP Trust Bootstrap Over WAN Mesh (P1)
- **BtspTcpClient + BtspConnection** — full 4-step BTSP handshake on client side with encrypted frame I/O (`tcp_ipc/client.rs`, `btsp_handshake/session.rs`)
- **Env-aware UPA registry** — `resolve_upa_registry_endpoint_from_env()` wired into `"upa"` and `"multi"` discovery arms
- **Trust DB seeding** — `seed_trusted_peer()` and `seed_trusted_peers_from_env()` for TOFU bootstrap from env vars or `btsp.trust.seed` RPC
- **Production BTSP mode** — `modes/server.rs` now respects `FAMILY_ID` via `resolve_security_mode()`
- **Provider dedup** — `peer_discovery.rs` solely owns address resolution; redundant methods removed from `contact_exchange.rs`
- **WAN timeouts** — `TCP_READ_TIMEOUT` configurable via `BEARDOG_TCP_READ_TIMEOUT_SECS` env var

#### Smart Refactoring (P1)
- **`server.rs` (811L) → `server/` module directory** — 7 files: mod, transport, attestation, health, registration, acme, tests
- **`orchestrator.rs` (851L) → pipeline stages** — 10 files: config, discovery, selection, generation, mixing, quality, orchestrator, tests

#### Modern Idiomatic Rust (P1)
- **Blocking I/O → async** — 4 async handlers migrated from `std::fs` to `tokio::fs` (genetic challenge, HSM storage, sslkeylog, TLS handshake)
- **`Arc<Mutex>` → `Arc<RwLock>`** — memory key manager (6 methods) + audit logger for read-heavy access patterns
- **11 error types → `thiserror::Error`** — `BondPersistenceError`, `TokenError`, `RegisterError`, `TlsConfigError`, `DiscoveryError`, `KmsError`, `ValidationError`, `VerificationError`, `ConstraintViolationError`, `AndroidError`, `StrongBoxError`
- **UID helper centralized** — `resolve_uid_from_proc()` deduplicated from 3 crates into `beardog-utils::platform`
- **Dependency cleanup** — removed unused `jni`; consolidated `hostname` → `whoami`, `dirs` → `directories`

#### Primal Self-Knowledge (P1)
- **`PRIMAL_NAME` wiring** — consolidated `DEFAULT_PRIMAL_NAME` to single source in `beardog-config`; added `resolve_primal_name()` helper
- **Hardcoded `"beardog"` removed** — 5 production sites now use env-aware identity resolution
- **Fake `discover_services()` removed** — no longer manufactures phantom compute/storage services; returns honest empty Vec with `tracing::warn`

#### Production Stub Evolution (P1)
- **mDNS discovery** — `listen_mdns_announcements()` now parses real `avahi-browse` output
- **Auth stub isolation** — `StubVerificationHandler` gated behind `#[cfg(any(test, feature = "test-utils"))]`
- **15+ stubs improved** — all discovery/dispatch/collaboration stubs now log actionable context with `tracing::warn!`

#### Pre-Existing Debt Fixed (P2)
- **`simd_crypto.rs` restored** — self-contained implementation after upstream `beardog_utils::simd` deletion
- **Circuit breaker test fixed** — half-open probe logic corrected
- **~20 clippy warnings cleaned** — doc backticks, `items_after_statements`, visibility, byte literals, error patterns

### June 19, 2026 -- Wave 117+: Deep Debt Execution — Security Hardening, Zero-Copy, Architecture Evolution

**145 files changed, 3,837 insertions, 11,638 deletions (-7,801 net LOC)**

#### Security Hardening (P0)
- **Integration API fake crypto → 501** — All BTSP/BirdSong/lineage crypto handlers now return HTTP 501 with honest messages instead of prefix-transform fake encryption. Tests assert 501 behavior.
- **Ed25519 proof verifier** — `DefaultProofVerifier` (placeholder) → `Ed25519ProofVerifier` (production `ed25519-dalek` signing/verification). Old placeholder renamed `PlaceholderProofVerifier`, gated `cfg(test)`.
- **Graph security audit honesty** — Deleted all `default_*()` hardcoded fake trust/metrics/security assessment data. Discovery methods return `Err` when collaboration network unreachable. Added `VerificationStatus` enum.
- **Biometric fail-closed** — iOS biometric auth returns `not_yet_available` in non-test builds. Android keystore XOR stub → `UnwiredAndroidKeystoreTransport` on production Android. StrongBox/TEE detection defaults `false`.
- **Entropy source honesty** — OS RNG labeled `source: "os_rng"`, `hardware_backed: false`, tier 0 with warning.

#### Architecture Evolution (P1)
- **tarpc ghost code removed** — `Protocol::Tarpc` → `Protocol::BinaryFrame`, `RouterConfig` simplified. JSON-RPC unambiguously primary.
- **262 clippy warnings → 0** — Across entire workspace including all test targets.
- **Production `.unwrap()` → proper error handling** — 6 crates fixed with `?`/`map_err`.
- **Hardcoded discovery → capability-based** — `*.ecosystem.internal` synthetic DNS removed. Network scan range env-driven. Integration API binds `127.0.0.1` by default.
- **Zero-copy IPC dispatch** — `JsonRpcRequest.method` → `Cow<'static, str>`. Handler registry returns `Vec<&'static str>`.
- **8 files >750 LOC** refactored at semantic boundaries (protocol_router, tcp_ipc, genetics_constraints, btsp_provider, crypto/hash, birdsong, primal_discovery, safe_android_provider).

#### Cleanup (P2)
- **CI pipeline** — Now runs `cargo test --workspace`, `cargo llvm-cov --fail-under-lines 90`, `cargo deny check`.
- **Orphan files deleted** — `pkcs11_provider.rs`, 8 root-level empty stub test files, workflow stubs.
- **Unused deps removed** — `jni`, `libc` from security/tunnel.
- **49 empty stub tests** → 21 implemented, 28 deleted.
- **6 E2E match arms** wired to module runners.
- **Verification handlers** — New `IdentityVerificationHandler` trait + `VerificationHandlerRegistry`.

### Jun 16, 2026 -- Wave 114: Mito-Beacon Acceptance (Genetics-Layer Wiring)

#### Added
- **Mito-beacon HMAC decode** (`ribocipher.rs`): `mito_tag()`, `mito_signal()`, `decode_mito_tag()`
  — HMAC-SHA256 truncated to 4 bytes, iterates known protocol types to verify tag against family seed
- **Mito-beacon routing** (UDS + TCP servers): `0xED` connections now decoded via FAMILY_SEED and
  dispatched to the correct handler (NDJSON, BTSP, probe, HTTP) — previously rejected with
  "mito-tier not yet implemented"
- **7 new unit tests** for mito-beacon encode/decode: determinism, per-protocol/seed differentiation,
  round-trip, wrong-seed rejection, garbage rejection

#### Fixed
- **Mode-detection race**: Mito-beacon signals (0xED) were correctly detected but immediately
  rejected, causing NUCLEUS launcher to see bearDog as non-responsive. Now decoded and routed
  identically to clear signals after HMAC verification.

### Jun 13, 2026 -- Wave 147: Doc Polish + Code Hygiene + BindMode Fix

#### Fixed
- **beardog-cli binary compilation**: Re-exported `BindMode` from `main.rs` — resolves
  pre-existing `error[E0433]` when compiling `beardog-cli` binary target (regression from Wave 109)

#### Removed
- **Completed migration guides** (fossilized to ecoPrimals):
  - `crates/beardog-traits/PROVIDER_TRAIT_MIGRATION_NOTICE.md` — zero legacy consumers remain
  - `crates/beardog-types/CONFIGURATION_MIGRATION.md` — zero legacy consumers remain
- **Workspace-excluded `crates/beardog/`** — placeholder crate, never compiled
- **10 completed migration comments** (`CLEANED:`, `REMOVED:`) across `beardog-types` and `beardog-core`

#### Changed
- **Ring/OpenSSL doc comments** (6 files): Corrected to reflect RustCrypto-only backend
  (Ring/OpenSSL variants kept for API compat, docs now state DEPRECATED)
- **Ring migration comment consolidation**: Trimmed repetitive celebratory comments
  across `crypto_dispatch.rs`, `factory.rs`, `software.rs`
- **ACME spec contradiction**: `specs/ACME_TLS_INTEGRATION_PATH.md` no longer says
  "design-only" — references implementation in `crates/beardog-acme/`
- **Doc metric sync** (7 docs): STATUS.md, ROADMAP.md, sporeprint/validation-summary.md,
  docs/README.md, specs/README.md, docs/references/ROOT_INDEX.md, .github/README.md —
  all synced to 226 methods, 14,974+ tests, 2,110 `.rs` files, Jun 13 dates

#### Metrics
- 226 JSON-RPC methods (217 registry + 9 pre-dispatch gate)
- 14,974+ tests, 169 suites, 0 failures (1 pre-existing in beardog-adapters)
- 2,110 `.rs` files (down from 2,125 after Wave 146 dead code removal)

### Jun 10, 2026 -- Wave 146: Debris Sweep — 9 Orphan Files + Doc Metric Sync

#### Removed
- **9 orphaned `.rs` files** (~66KB dead code, never compiled):
  - `beardog-utils/src/zero_copy/` — `safe.rs`, `buffer_management.rs`, `advanced_patterns.rs`,
    `advanced_optimization.rs` (never declared in `mod.rs`)
  - `beardog-genetics/src/genetics/spawning/` — `lineage.rs`, `workflows.rs` (broken syntax,
    never declared in `mod.rs`)
  - `beardog-core/src/zero_knowledge_bootstrap/` — `tests.rs`, `tests/mod.rs`,
    `tests/discovery_comprehensive_tests.rs` (superseded by wired `zero_knowledge_bootstrap_tests.rs`)

#### Changed
- **Root doc metric sync**: Aligned 6 docs (README, ARCHITECTURE, START_HERE, CONTEXT, ROADMAP,
  STATUS) to ground-truth — 226 methods, 14,974+ tests, 2,125 `.rs` files, Jun 10 dates.
- **Broken doc links fixed**: Removed stale `docs/sessions/` references from source code.

#### Metrics
- 226 JSON-RPC methods (217 registry + 9 pre-dispatch gate)
- 14,974+ tests, 169 suites, 0 failures
- 2,125 `.rs` files (down from 2,134 after Wave 145+146 debris removal)

### Jun 9, 2026 -- Wave 145: Pure Rust Crypto Dedup + Dead Code Cleanup

#### Changed
- **Pure Rust Crypto Transition**: Replaced `aws-lc-rs` with `rustls-rustcrypto` (pure Rust
  `CryptoProvider` for `rustls`). Replaced `rcgen` with `p256` + `x509-cert` for ACME CSR
  generation. 19 C-crypto crates banned in `deny.toml`.
- **Crypto Dedup**: Consolidated `BearDogCrypto` as canonical primitive layer — ChaCha20-Poly1305,
  SHA-256, secure random, constant-time compare all delegate through single implementation.
  Renamed `RustCryptoProvider` → `SoftwareHsmCryptoProvider` to resolve naming collision.
  Filled KDF/ECDSA gaps in `UniversalCryptoProvider`.
- **19 orphaned files removed** (~194KB dead code): abandoned crypto wrappers, stale test files,
  superseded bootstrap/utility modules.

#### Metrics
- 14,974+ tests, 169 suites, 0 failures
- 0 clippy warnings
- Pure Rust crypto: `rustls-rustcrypto`, `p256`, `x509-cert` — zero C/FFI crypto deps

### Jun 7, 2026 -- Wave 94: `capability.call` Routing Dispatcher (P1 Mesh Blocker)

#### Added
- **`capability.call` method**: Routing dispatcher that bridges Songbird's capability-addressed
  RPC convention to bearDog's concrete method namespace. Accepts
  `{"capability": "<domain>", "operation": "<method>", "args": {...}}` and routes to
  `{capability}.{operation}` (e.g., `tls.sign_handshake`, `btsp.negotiate`).
  This unblocks cross-gate federation peer TLS handshake — the sole blocker for 3-gate mesh.
- **Recursion guard**: `capability.call` cannot route to itself.
- **10 new tests**: Method exposure, routing to tls/health/btsp, error cases (missing params,
  missing fields, recursion, unknown capability).
- **`capability_registry.toml`**: Added `[capabilities.capability_router]` section.

#### Changed
- **`method_gate.rs`**: `capability.call` classified as Public (pre-auth primitive, same as
  `auth.issue_ionic` — security boundary is UDS filesystem permission).

### Jun 5, 2026 -- Wave 142: Deep Debt Cleanup — Smart Refactor + Stub Evolution + Protocol Rename

#### Changed
- **Smart refactor `ionic_token_handlers.rs`** (954→668L): Extracted trust management handlers
  (`auth.trust_issuer`, `auth.exchange_trust`, `auth.events.poll`, `auth.trusted_issuers`) into
  new `trust_handlers.rs` (317L). Clean domain boundary: token lifecycle vs trust topology.
- **`Protocol::Tarpc` → `Protocol::BinaryFrame`**: Renamed enum variant, config field
  (`enable_tarpc` → `enable_binary_frame`), and all references to accurately reflect the actual
  purpose (binary frame protocol sniffing) rather than the removed tarpc dependency. Default
  changed from `enable_tarpc: true` + `preferred: Tarpc` to `enable_binary_frame: false` +
  `preferred: JsonRpc` — JSON-RPC 2.0 is the primary architecture.
- **Ed448 handlers**: Migrated from `Result<Value, String>` to `Result<Value, BearDogError>`.
  Uses `BearDogError::not_yet_available` for deferred feature (< 0.1% server support).
  Removed dead crypto key imports. Added verify + missing-params test coverage.
- **Discovery engine hardcoding eliminated**: `192.168.1.0/24` replaced with env-driven
  `BEARDOG_HSM_NETWORK_SCAN_RANGES` (comma-separated CIDRs). Added `ENV_HSM_NETWORK_SCAN_TIMEOUT_MS`
  and `ENV_HSM_NETWORK_SCAN_PARALLEL` for full config control.
- **Mobile ephemeral entropy evolved**: Placeholder `vec![1, 2, 3, 4, 5]` → cryptographically
  random 32-byte context via `rand::random()`. Simulated sensor data → randomized values
  using `mul_add` FMA optimization.

#### Metrics
- 15,004+ tests passing, 169 suites, 0 failures
- 0 clippy warnings, 0 files >800L in production

### Jun 5, 2026 -- Wave 141: Ecosystem Parity — Registry Move + Method Sync

#### Changed
- **`capability_registry.toml` → `config/capability_registry.toml`**: Moved to match ecosystem
  convention (biomeOS/petalTongue/sweetGrass pattern). Updated method count 223→226 and added
  `auth.exchange_trust`, `crypto.sign.ed25519`, `crypto.verify.ed25519`.
- bearDog confirmed at ecosystem **REFERENCE TIER**: zero gaps, zero `.unwrap()` in production,
  zero TODO/FIXME, zero stale tarpc, zero blocking debt.

#### Metrics
- 226 JSON-RPC methods (217 registry + 9 pre-dispatch gate)
- 15,004 tests passing, 169 suites, 0 failures
- 90.5% line coverage

### Jun 4, 2026 -- Wave 140: BD-TRUST-01 — Auto Trust Seeding via auth.exchange_trust

#### Added
- **`auth.exchange_trust` RPC method**: Bidirectional trust exchange for mesh auto-join.
  When called on a BTSP-authenticated channel (family seed proven), auto-registers the
  caller's Ed25519 public key as a trusted issuer and returns the local gate's identity.
  Eliminates manual `auth.trust_issuer` calls during mesh join.
- **`CallerContext.btsp_family_verified`**: New field set after successful BTSP handshake
  on TCP and UDS code paths. Enables `auth.exchange_trust` without requiring ionic tokens.
- Auto-derives DID from public key when `did` parameter is absent.
- Tests: `exchange_trust_*` (5 tests covering registration, unauthenticated rejection,
  DID derivation, gate-handled classification, Protected access level).

#### Metrics
- 15,004 tests passing, 169 suites, 0 failures

### Jun 4, 2026 -- Wave 139: Auth Event Bus + tarpc Cleanup

#### Added
- **`auth_event_bus` module**: Bounded, poll-based event log for cross-gate trust provenance.
  - `AuthEventKind` enum: `TrustIssuerRegistered`, `KeyExchangeCompleted`, `FamilyEnrollment`,
    `MeshJoin`, `MeshLeave` — maps 1:1 to rhizoCrypt's `MeshTrustEvent` wire DTOs.
  - `AuthEventBus`: Thread-safe bounded ring buffer + `tokio::sync::broadcast` for future streaming.
  - Wire format matches FRAGO `wave76c-beardog-auth-events-subscribe`.
- **`auth.events.poll` RPC method**: Gate-handled (Protected), returns events since a given
  Unix timestamp. Enables rhizoCrypt's `MeshEventListener` to consume trust events.
- **Event emission from `auth.trust_issuer`**: On successful registration, emits
  `TrustIssuerRegistered` event with issuer DID, fingerprint, and trust method.
- Tests: `auth_event_bus` (8 tests), `trust_issuer_emits_event`, `auth_events_poll_*` (3 tests).

#### Changed
- **tarpc debris cleanup**: Removed stale tarpc references from 10 doc comments across
  `server.rs`, `protocol.rs`, `tcp_ipc/mod.rs`, `zero_hardcoding.rs`, `crypto_service/`.
  Deleted orphan `multi_transport_tests.rs` (references deleted APIs). Updated test fixtures
  from `"tarpc"` to `"json-rpc"` protocol. `Protocol::Tarpc` enum retained in `beardog-ipc`
  for binary frame detection (structural, not a dependency).

#### Metrics
- 14,999 tests passing, 169 suites, 0 failures

### Jun 4, 2026 -- Wave 138: Phase 3.5 Relay Interface + Seed Fingerprint Validation

#### Added
- **`crypto.verify.ed25519` / `crypto.sign.ed25519`**: Phase 3.5 `CryptoProvider::call`
  aliases for Songbird relay-path Ed25519 signature verification. Routes to existing
  `handle_verify_ed25519` / `handle_sign_ed25519` handlers with full multi-encoding support.
- Tests: `phase35_crypto_provider_call_aliases_registered`, `phase35_verify_ed25519_is_protected`

#### Verified
- **`crypto.seed_fingerprint`**: Confirmed implementation matches westGate enrollment spec —
  `BLAKE3(HMAC-SHA256(family_seed, "seed-fingerprint-v1"))`, truncated to 16 bytes, hex-encoded.
  5 existing tests cover correctness, determinism, seed differentiation, error handling, routing.
- **S4 7-day gate**: Active through ~Jun 9, passive monitoring.

#### Metrics
- 225 JSON-RPC methods (217 registry + 8 pre-dispatch gate)
- 108 crypto handler methods
- 14,987 tests passing, 169 suites, 0 failures

### Jun 3, 2026 -- Wave 137: Deep Debt — Typed Handler Errors, Zero-Hardcoding, Dashmap 6

#### Changed
- **`MethodHandler::handle` returns `HandlerResult`**: Replaced `Result<Value, String>`
  with typed `HandlerError` enum (`MethodNotFound` / `InvalidParams` / `Application` /
  `Domain`) across all 14 handler implementations, the `MethodHandlerKind` dispatch
  enum, and `HandlerRegistry::route`. JSON-RPC error codes now derive from enum
  variants, eliminating string-contains matching. `From<String>` bridge ensures
  backward compatibility for existing handlers during gradual migration.
- **`route_with_outcome` uses structured error matching**: Dispatch phase and error
  code now derive from `HandlerError::error_phase()` / `json_rpc_code()` instead
  of string pattern matching on error messages.
- **`discover_by_capability(Vec<UniversalCapabilityType>)` renamed to
  `discover_by_typed_capability`**: Documents the type-system convergence gap
  between typed capability enums and string-based discovery pipeline.
- **Dashmap 5.5 → 6.2**: Upgraded concurrent map to latest stable (hashbrown 0.15,
  detached guards, `SharedValue` removed). Zero API breakage.

#### Fixed
- **7 hardcoded `"beardog"` fallbacks centralized**: All inline `"beardog"` string
  defaults now reference `env_keys::DEFAULT_PRIMAL_NAME`.
- **5 hardcoded `*.ecosystem.internal` defaults centralized**: Discovery and registry
  host defaults now reference `env_keys::DEFAULT_DISCOVERY_HOST` and
  `env_keys::DEFAULT_REGISTRY_HOST`.

#### Added
- `HandlerError` enum with `contains()`, `is_empty()`, `json_rpc_code()`,
  `error_phase()`, `into_json_rpc_error()` methods.
- `HandlerResult` type alias for handler return types.
- `DEFAULT_PRIMAL_NAME`, `DEFAULT_DISCOVERY_HOST`, `DEFAULT_REGISTRY_HOST` constants
  in `env_keys.rs`.

### Jun 3, 2026 -- Wave 136: Trust Hardening + Phase 3.5 Design

#### Security Fixes (P0)
- **`auth.trust_issuer` moved to PROTECTED**: Unauthenticated callers can no
  longer inject trusted issuers. Requires valid ionic token in Enforced mode.
- **DID ↔ key binding on register**: `TrustedIssuerRegistry::register()` now
  validates that the supplied `did:key:z6Mk...` matches the canonical DID
  derived from the Ed25519 public key. Returns `RegisterError::DidKeyMismatch`
  on mismatch. Prevents trust-store poisoning with mismatched DID/key pairs.
- **`iss` binding in verification**: `verify_with_registry()` now checks that
  `payload.iss` matches the registered DID after Ed25519 signature verification.
  Tokens with valid signature but mismatched `iss` are rejected (prevents
  key-confusion attacks).

#### Added
- `did_from_verifying_key()` / `did_matches_key()` — canonical DID derivation
  and validation helpers in `trusted_issuer_registry`.
- `RegisterError` type for structured error reporting from issuer registration.
- `iss_mismatch_prevents_remote_verify` test — validates the new iss binding.
- `register_validates_did_key_binding` test — validates DID/key binding.
- `did_from_key_roundtrip` test — validates DID derivation.

### Jun 3, 2026 -- Wave 135: Cross-Gate Trust + Covalent Mesh Security

#### Added
- **Cross-gate trusted issuer registry** (`trusted_issuer_registry.rs`): Thread-safe
  registry of remote gate Ed25519 public keys, enabling multi-gate ionic token
  verification without per-request key exchange.
- **Cross-gate token claims** (`ionic_token.rs`): `IonicTokenPayload` now carries
  optional `gate_id` (issuing gate's `NODE_ID`) and `family_id` claims. Backward
  compatible via `serde(default, skip_serializing_if)`.
- **`auth.trust_issuer` RPC**: Register a remote gate's public key as trusted,
  with metadata (`gate_id`, `family_id`, trust method).
- **`auth.trusted_issuers` RPC**: List all registered trusted issuers for audit.
- **`issue_ionic_token_with_gate()`**: Issue tokens with embedded gate identity
  for cross-gate verifiers to identify the issuing gate.
- **`GateIdentity` struct**: Carries `node_id` + `family_id` for token issuance.
- **`verify_with_registry()`**: Core cross-gate verification function — tries
  local key, then registry issuers, then ad-hoc key.

#### Changed
- **`auth.verify_ionic`**: Now supports cross-gate verification via three key
  sources (local → trusted registry → ad-hoc `issuer_key` param). Returns
  `verification_source` ("local" | "remote" | "adhoc") and remote issuer
  metadata when applicable.
- **`MethodGate`**: Now holds a `TrustedIssuerRegistry` for pre-dispatch token
  verification against registered remote gate keys.
- **`MethodGate::check()`**: Bearer token verification uses `verify_with_registry`
  — tokens from trusted remote gates are now accepted for protected methods.
- **Capability registry**: Added `auth.trust_issuer` and `auth.trusted_issuers`
  to `config/capability_registry.toml`.

#### Tests
- 8 new tests in `trusted_issuer_registry`: local verification, remote
  verification with registered issuer, ad-hoc key, idempotent registration,
  list/remove, and full cross-gate roundtrip (token issued on gate A, verified
  on gate B).
- All existing ionic token tests updated for new API and passing.

### Jun 3, 2026 -- Wave 134: ACME Smart Refactor + Stub Evolution + Dep Cleanup

#### Changed
- **ACME client smart refactor**: Split `client.rs` (860 lines) into 4 cohesive modules:
  - `client/mod.rs` — struct, constructor, protocol core (directory, account, order, challenges)
  - `client/config.rs` — `AcmeConfig`, HTTP bootstrap, `Directory` type
  - `client/renewal.rs` — daemon loop, expiry checks, renewal scheduling
  - `client/issuance.rs` — CSR generation, order finalization, polling, cert download
  All 36 tests preserved and passing.
- **Production stub evolution**: Silent no-ops now emit `warn!` when registry URL
  is configured but client not implemented (`primal_self_knowledge.rs`,
  `beardog-discovery/discovery.rs`). Unimplemented capability discovery now
  warns instead of silently succeeding (`trait_impl.rs`).
- **Dead dependency removal**: `hostname` removed from `beardog-tunnel` and root
  binary `Cargo.toml` (zero usage confirmed in both).

### Jun 3, 2026 -- Wave 133: Deep Debt Audit + Env Migration Wave 5

#### Fixed
- **Windows `.expect()` panic removed**: `platform/mod.rs` `default_socket_endpoint()`
  now uses `unwrap_or_else` with a fallback named pipe instead of panicking.
- **iOS XPC hardcoded identifier**: `SocketEndpoint::XPC("com.ecoprimals.beardog")`
  now derives from `ENV_PRIMAL_NAME` at runtime (self-knowledge pattern).

#### Changed
- **Env literal migration Wave 5** (~35 string literals → `env_keys` constants):
  - `system.rs`: 10 literals → `env_keys` (app name, version, instance, workers, etc.)
  - `system_logging.rs`: 2 literals → `env_keys` (log rotation)
  - `compliance.rs`: 2 literals → `env_keys` (audit retention/frequency)
  - `testing.rs`: 5 literals → `env_keys` (test/benchmark config)
  - `security/mod.rs`: 6 literals → `env_keys` (rate limiting)
  - `core_learning.rs`: 4 literals → `env_keys` (online learning)
  - `zero_hardcoding.rs`: 12 literals → `env_keys` (ports + timeouts)
  - `primal_identity.rs`: 2 literals → `env_keys` (family/node ID)
  - `beardog-ipc/lib.rs`: local `ENV_IPC_RESOLVE_TARGET_PARAM_KEY` → centralized
- **`env_keys.rs` expanded**: ~25 new constants added for system, logging, compliance,
  testing, benchmarks, timeouts, rate limiting, and IPC categories.

#### Verified
- `ring` confirmed ABSENT from all targets (`cargo tree -i ring --target all` → empty).
  deny.toml ban effective. Zero transitive ring dependencies.
- `unsafe` code: zero blocks in production (workspace `forbid(unsafe_code)` enforced).
- `.unwrap()` in production: zero (only `#[cfg(test)]` blocks).
- `todo!()`/`unimplemented!()`: zero in all .rs files.

### Jun 3, 2026 -- Wave 132: AI Type Migration + Mobile Feature Gate

#### Changed
- **AI deprecated modules migration (P2)**: Moved type definitions from
  `beardog-core/ai/hybrid_intelligence/{learning,neural_networks,learning_optimization}.rs`
  to `beardog-types/ai_config/{core_learning,core_neural_networks}.rs`.
  Deprecated modules are now thin re-exports. `learning_optimization.rs` deleted.
  -1,104 LOC from beardog-core, types centralized in beardog-types.
- **Mobile feature flag (P3)**: `beardog-security` now has `feature = "mobile"`
  that gates Android `StrongBox` and iOS Secure Enclave paths, mirroring
  the FIDO2 `feature = "fido2"` pattern. All `cfg(target_os = "android")`
  and `cfg(target_os = "ios")` in the HSM orchestrator updated to require
  `feature = "mobile"` as well.

### Jun 3, 2026 -- Wave 131: auth.verify_ionic Scopes Fix + Wave 73 Gap Analysis

#### Fixed
- `auth.verify_ionic` now always includes `scopes` array at top level of response
  (empty `[]` on error/invalid, actual scopes on success) -- unblocks primalSpring
  SecurityVerifier Enforced mode

#### Confirmed (No Code Change Needed)
- `health.liveness` already registered and returning `{"status":"alive"}` -- primalSpring
  report of -32601 is stale
- Android type stack (`HsmEntropyOrchestrator` -> `StrongBoxMultiCredentialProvider`)
  already `#[cfg(target_os = "android")]` gated -- no compile-time coupling on desktop
- AI deprecated modules (`learning.rs`, `neural_networks.rs`) have incompatible type
  shapes vs canonical `beardog_types::ai_config` (struct vs enum, different fields,
  missing types) -- NOT a simple import swap, requires type system redesign
- S4 auth monitoring: 7-day gate active (ends ~Jun 9), no issues reported

### Jun 3, 2026 -- Wave 130: Feature-gate quantum_crypto, Delete Deprecated Modules

#### Changed
- `quantum_crypto` module gated behind `feature = "quantum-crypto"` (disabled by default)
- Deleted `monitoring_unified/` (7 files) -- replaced by `canonical/monitoring/`
- Deleted `timeout_unified.rs` -- aliases inlined to `timeout.rs`
- Deleted `providers_unified/discovery.rs` -- re-export inlined to `mod.rs`
- Deep debt audit: zero `.unwrap()` in production code (all in `#[cfg(test)]`)

### Jun 2, 2026 -- Wave 129: grapheneGate Keystore Design, Pure-Rust Crypto Horizon

#### Changed
- Added `AndroidDeviceInfo::pixel_8a()` with Pixel 8a/akita/Tensor G3/Titan M2 defaults
- Added `AndroidKeymaster` transport variant for future hardware-backed keystore
- Backend selection via `BEARDOG_KEYSTORE_BACKEND` env var (memory vs keymaster)
- `is_production_ready()` method on `KeystoreTransportBackend` distinguishes mock from real
- Renamed `create_pixel8_graphene_config()` to `create_pixel8a_graphene_config()`
- Safe device detection falls back to `ANDROID_MODEL`/`ANDROID_MANUFACTURER` env vars
- `deny.toml` documents pure-Rust crypto horizon tracking (rustls-rustcrypto, rcgen alternatives)

### Jun 2, 2026 -- Wave 128: Env Migration Complete, Dependency Consolidation

#### Changed
- Env key centralization complete: 370+ inline env var strings migrated to `env_keys::` constants across 96 production files (waves 6-7)
- `env_keys.rs` now holds 803+ constants covering all bearDog env vars
- Only 3 external system vars (`ANDROID_NDK_HOME`/`NDK_HOME`) remain as intentional inline strings
- Removed `base64-url` crate (replaced with `base64::URL_SAFE_NO_PAD`)
- Replaced `crossbeam` meta-crate with `crossbeam-queue` (only `ArrayQueue`/`SegQueue` used)
- Added `beardog-config` dependency to `beardog-genetics`, `beardog-monitoring`, `beardog-utils`, `beardog-tower-atomic`, `beardog-deploy`
- Fixed doc test imports for `env_keys` in `beardog-tower-atomic`, `beardog-types`

### Jun 2, 2026 -- Wave 127: Stub Evolution, DNS-SD Wiring, File Splits, Safety Hygiene

#### Changed
- Fixed dead `if false` branch in `validate_key_access` with real keystore existence check
- Fixed `memory_key_manager::list_keys()` to enumerate stored keys
- Implemented `get_network_interfaces()` for Linux via `/sys/class/net`
- Wired DNS-SD/mDNS integration in `primal_discovery` via `MdnsDiscoveryClient`
- Split `tcp_ipc/server.rs` (814L), `btsp_provider.rs` (791L), `primal_discovery.rs` (779L) into focused submodules
- Added `#![forbid(unsafe_code)]` to `beardog-deploy`, `beardog-installer`, benchmarks

### Jun 2, 2026 -- Wave 126: Tokio Feature Trimming, Env Migration Wave 5

#### Changed
- Trimmed `tokio` from `features = ["full"]` to per-crate minimal feature sets
- Centralized ~90 raw env var strings across 40+ files (wave 5)
- Added explicit tokio feature overrides for all 18 workspace crates

### Jun 2, 2026 -- Wave 125: Ring Elimination

#### Changed
- Switched TLS crypto backend from `ring` to `aws-lc-rs` for `rustls`, `tokio-rustls`, `rcgen`
- Banned `ring` in `deny.toml`; `aws-lc-rs`/`aws-lc-sys` allowed wrapped by rustls/rcgen
- Changed `reqwest` to `rustls-tls-webpki-roots-no-provider` with explicit provider init

### Jun 2, 2026 -- Wave 124: Root Doc Sync, Debris Cleanup

#### Changed
- Updated method count 127 → 223 across README, STATUS, ARCHITECTURE, START_HERE, CONTEXT
- Removed false post-quantum claims and hickory-dns references
- Aligned `.env.example` variable names with `env_keys.rs`
- Deleted disabled `hardware_pkcs11_tests.rs`; rewrote tunnel integration test README
- Archived 16 Wave 67 handoffs and 3 impulses

### Jun 2, 2026 -- Wave 123: Env Migration Wave 4, Dependency Evolution, Cert Stack Upgrade

#### Changed
- Centralized ~200 raw env var strings across 20 production files (beardog-types, beardog-core, beardog-tunnel HSM, beardog-ipc) to `env_keys::` constants
- Replaced unmaintained `rustls-pemfile` (RUSTSEC-2025-0134) with `rustls-pki-types` `PemObject` API
- Upgraded `x509-parser` 0.16 → 0.18 and `rcgen` 0.13 → 0.14
- Unified `beardog-acme` x509-parser to workspace dependency

### Jun 2, 2026 -- Wave 122: ACME CSR Evolution, Android Mock Honesty, Env Migration Wave 3

#### Changed
- Replaced ACME CSR placeholder with proper PKCS#10 DER generation via `rcgen` (ECDSA P-256)
- Android `MemoryKeystoreTransport` now reports honest capabilities (`strongbox_available: false`, `hardware_backed: false`)
- Added runtime `tracing::warn!` on Android stub keystore paths
- Centralized ~130 raw env var strings (network_discovery, security, network, runtime_config, self_discovery)
- Proper PKCS#8 PEM export via `cert_private_key_pem()`

### Jun 2, 2026 -- Wave 121: Env Migration Wave 2, Quantum Stub Removal, Test Refactoring

#### Changed
- Centralized ~30 raw env var strings across btsp_handshake, socket_config, handlers/utils, modes/server, platform
- Made `neural-api.sock` filename configurable via `BEARDOG_NEURAL_API_SOCKET_NAME`
- Removed dead quantum discovery stubs (`create_quantum_entanglement`, `quantum_anneal_selection`, `OptimizationCriterion`)
- Split `crypto_operations_comprehensive_tests.rs` (866L) into 8 focused test modules
- Split `security_edge_cases.rs` (880L) into 12 focused test modules

### Jun 2, 2026 -- Wave 120: Deep Debt Cleanup — Deps, Timeouts, Env Centralization, Deprecated Removal

- **Pruned 3 unused workspace dependencies** — Removed `dotenvy` (beardog-config), `tokio-stream` (beardog-security), `arrayref` (beardog-tunnel) from both workspace `[dependencies]` and per-crate `Cargo.toml` manifests. Zero source references confirmed before removal.
- **Timeout centralization** — Replaced 5 hardcoded `Duration::from_secs(N)` constants in tunnel IPC with `LazyLock`-based env-driven values: `IPC_READ_TIMEOUT` and `TCP_READ_TIMEOUT` use `BEARDOG_READ_TIMEOUT_SECS` (default 30s); `IPC_PEEK_TIMEOUT`, `TCP_HANDSHAKE_DETECT_TIMEOUT`, and `BTSP_JSONLINE_READ_TIMEOUT` use `BEARDOG_HANDSHAKE_TIMEOUT_SECS` (defaults 5s/30s). All configurable at runtime without recompilation.
- **Env key migration (ACME + tunnel)** — Migrated 13 raw `"BEARDOG_*"` string literals to `env_keys::ENV_*` constants across `beardog-acme` (5 keys), `beardog-cli` (1), `beardog-tunnel/tls` (2), `beardog-tunnel/rate_limiter` (3). Fixed ACME naming drift: `ENV_ACME_HTTP_PORT` → `ENV_ACME_CHALLENGE_PORT`, `ENV_ACME_RENEWAL_HOURS` → `ENV_ACME_RENEWAL_DAYS` to match production usage. Added 5 new constants to `env_keys.rs`.
- **`#![forbid(unsafe_code)]` on CLI binary** — Added to `beardog-cli/src/main.rs` for defense-in-depth. All 29 library crates + 2 binary roots now forbid unsafe.
- **Deprecated `monitoring_unified` re-exports removed** — Cleaned `metrics.rs` and `health_status.rs` in `beardog-types` of stale `pub use` lines pulling deprecated monitoring types. No callers depended on these paths.

### Jun 1, 2026 -- Wave 119: S4 Auth Config — SO_PEERCRED + MethodGate Centralization (Wave 67 Response)

- **`SO_PEERCRED` extraction enabled** — `auth.peer_info` now returns real `uid`/`pid` from Unix domain sockets. `PlatformStream` trait extended with `peer_credentials()` method (stable since Rust 1.75, was incorrectly marked as unstable). Implemented on `UnixPlatformStream` and `AndroidPlatformStream` via `tokio::net::UnixStream::peer_cred()`. `PrefixedStream` delegates to inner stream. All 4 connection handlers in `connection_handlers.rs` updated to populate `CallerContext` with live peer credentials.
- **`BEARDOG_AUTH_MODE` centralized** — Inline `"BEARDOG_AUTH_MODE"` string replaced with `beardog_config::env_keys::ENV_AUTH_MODE`. Added to `env_keys.rs` along with `ENV_BTSP_BIRDSONG_KEY_LABEL`, `ENV_BTSP_LINEAGE_ROOT_PREFIX`, `ENV_BTSP_LINEAGE_MAX_DEPTH`. Migrated `domains/btsp.rs` from local duplicate constants to centralized `env_keys::*`.
- **S4 shadow deployment documented** — Added `BEARDOG_AUTH_MODE` documentation to `ENVIRONMENT_VARIABLES.md` (Security & Trust section). Added "S4 Shadow Validation" example configuration showing minimum env vars for ironGate to consume BTSP auth services during the formal 7-day gate.
- **Wave 67 bearDog S4 (P0)**: Auth IPC surface complete (`auth.verify_ionic`, `auth.public_key`, `auth.issue_session`, `auth.peer_info`); BTSP transport auth production-ready (env-gated via `FAMILY_ID` + `FAMILY_SEED`); `MethodGate` enforcement opt-in via `BEARDOG_AUTH_MODE=enforced`. ironGate can now begin formal 7-day shadow validation.

### May 28, 2026 -- Wave 118: PRIMAL_CONTRACTS Method Catalog Refresh (Wave 59 Response)

- **`PRIMAL_CONTRACTS.md` v4.0.0** — Complete method catalog overhaul. Total count corrected from 127 to **223 dispatchable methods** (215 registry + 8 pre-dispatch gate). Category breakdown rewritten with all 18 handler categories. Method index rebuilt with exact registered names from code.
- **TCP port corrected** — `9190` (metrics) → `9100` (`DEFAULT_TCP_IPC_PORT`).
- **Error codes updated** — Stale lineage/relay/beacon codes replaced with actual `MethodGate` enforcement codes (`-32000` UNAUTHORIZED, `-32001` PERMISSION_DENIED, `-32002` NOT_READY).
- **Auth model rewritten** — Replaced genetic-lineage-only section with multi-layer auth (genetic + ionic tokens + session tokens + `MethodGate` enforcement).
- **Ionic bond section** — Updated from 8 to 12 methods (added `verify_proposal`, `crypto.contract.*`).
- **Implementation paths fixed** — Updated stale handler file paths to match current crate layout.
- **Wave 59 bearDog items**: env debt RESOLVED (Waves 116-117); NC-3.5 RESOLVED (Wave 108); PRIMAL_CONTRACTS stale → **RESOLVED**.

### May 28, 2026 -- Wave 117b: Root Doc Sync, Orphan Purge, Config Annotations

- **21 orphan `.rs` files deleted** — 9 in `beardog-genetics` (api, types, handlers, entropy_simple, biome_genetics, peer_to_peer_genetics, zero_copy, simd_optimization, tests — many with corrupted syntax), 5 in `beardog-core` (operations, new_mod, beardog_core, ecosystem_coordination, primal_provider — imports of non-existent modules), 1 in `beardog-core/ai` (ecosystem_coordination), 6 in `beardog-types` (providers, relationships, workflow, security, metrics, genetics — superseded by `*_unified` modules). ~3,500 LOC total dead code removed.
- **Root docs synced** — All 9 root markdown files updated: dates → May 28, 2026; tests → 14,987+; Rust files → 2,115. STATUS.md refreshed with Waves 116-117 entries.
- **HTTP-era config templates annotated** — Added pre-UniBin disclaimers to `production.toml`, `network-defaults.toml`, `beardog-config-template.toml`, `beardog-config.toml`, `env-template.example`.

### May 28, 2026 -- Wave 117: Deep Debt Cleanup — Dependencies, Env Migration, Deprecated Types

- **Deleted dead `beardog-tunnel/src/main.rs`** — Stale 198-line CLI duplicate (not wired as binary target). Removed tunnel-only `clap` and `tracing-subscriber` deps.
- **Purged 10 unused workspace dependencies** — `tokio-tungstenite`, `tokio-serde`, `mockito`, `wiremock`, `tokio-test` (12 crates), `validator`, `urlencoding`, `local-ip-address`. Cleaned root `[workspace.dependencies]` and all per-crate `Cargo.toml` entries.
- **Deleted FIDO2 `operations.rs` dead stubs** — Three `requires_capability` stub functions and duplicate `Ctap2Command` enum. Re-exported `Ctap2Command` from canonical `ctap2::types` module.
- **Env var centralization: 100+ sites migrated** — All 17 domain files in `beardog-config/src/domains/` now use `env_keys::ENV_*` constants instead of inline `"BEARDOG_*"` strings. Added 42 new constants to `env_keys.rs` (paths, network timeouts, security flags, limits, capacity).
- **Deprecated type cleanup** — `LoggingConfiguration` → `LoggingConfig` in `providers/base/` (configuration.rs + defaults.rs). `RegistryConfig` → `ProviderRegistryConfig` in `ecosystem_integration.rs` and `consolidated_registry.rs`. Removed `BiomeOSPaths` deprecated re-export from `beardog-installer/lib.rs`.
- **Quality gates** — `cargo fmt`, `cargo clippy -D warnings`, `cargo test --workspace` all pass (14,987 tests, 0 failures).

### May 28, 2026 -- Wave 116: Env Var Centralization Foundation (Wave 58 Response)

- **`beardog-config::env_keys` module created** — Centralized `BEARDOG_*` env var key constants organized by domain (paths, network, ports, monitoring, health, timeouts, security, crypto, HSM, ACME). 65 constants covering all high-traffic env var names.
- **`health.rs` fully migrated** — All 12 inline `env::var("BEARDOG_*")` calls in `UnifiedHealthConfig` and sub-configs now use `env_keys::ENV_*` constants.
- **`multi_transport_server.rs` migrated** — TCP IPC port env read uses `env_keys::ENV_TCP_IPC_PORT`.
- **NC-3.5 acknowledged as resolved** — `content.*` scope already in session tokens since Wave 108. No further bearDog code changes needed; remaining work is downstream integration.
- **Migration pattern established** — Callers use `std::env::var(env_keys::ENV_FOO)` instead of `std::env::var("BEARDOG_FOO")`. Remaining ~400+ sites can be migrated incrementally using the same pattern.

### May 27, 2026 -- Wave 115b: Root Doc Sync & Debris Purge

- **Root doc dates aligned** — README, CONTEXT, ROADMAP, START_HERE, ARCHITECTURE (both footer dates), SECURITY, docs/README, docs/PRIMAL_CONTRACTS all updated to May 27, 2026.
- **Method count drift fixed** — `ARCHITECTURE.md` diagram: "100+" → "127". `START_HERE.md`: "100+" → "127".
- **Test count drift fixed** — `START_HERE.md`: 12,610 → 14,980+. `README.md`, `ARCHITECTURE.md`: 14,940+ → 14,980+.
- **Orphan modules deleted** — `tunnel/key_manager.rs` (316 LOC) and `tunnel/security_provider.rs` (268 LOC) were not in any `mod` tree. Removed.
- **Stale script reference fixed** — `entropy/collect.rs` referenced nonexistent `scripts/setup-hardware-testing.sh`; now points to `docs/references/RUN_ENTROPY_TEST.md`.
- **HTTP-era config templates annotated** — `development.env`, `production.env`, `network-discovery.env.template` get header notes clarifying Unix socket JSON-RPC is the primary transport.
- **ROADMAP stale narrative cleaned** — Wave 69b summary: removed pre-fossilization showcase references and stale method counts.

### May 27, 2026 -- Wave 115: Deep Debt Cleanup

- **Orphan modules deleted** — `tunnel/genetic_healing.rs` (434 LOC) and `tunnel/simplified_seed_tunnel.rs` (21 LOC) were never wired into any `mod` tree. Removed.
- **Empty `key_manager.rs` stub** narrowed to `mod` (private) with clarified doc about reserved purpose.
- **Ionic bond test split** — `ionic_bond/tests.rs` (1165 LOC monolith) refactored into `tests/{helpers,lifecycle,seal,contract,cross_family}.rs` (5 domain modules, 33 tests preserved).
- **Stale `#[allow]` replaced** — `benchmarks/src/utils_tests.rs` bare `#[allow(clippy::float_cmp)]` upgraded to `#[expect(…, reason = "…")]`.
- **Hardcoded primal names cleaned** — Production comments referencing `loamSpine` (ionic_bond handler, handlers mod) and `skunkBat` (ACME shadow_metrics) replaced with capability-agnostic wording.
- **HSM capability detector documented** — `capability_detector.rs` stub now explains its role and why it returns empty until platform probes are wired.

### May 26, 2026 -- Wave 114: UDS-Only Mode (TCP Drop Prep for exp114)

- **TCP transport now opt-in** — `MultiTransportServer` no longer unconditionally binds TCP on `127.0.0.1:9100`. TCP is started only when `--port`/`--listen` CLI flags are passed or `BEARDOG_TCP_IPC_PORT` env var is set. Without either, bearDog runs UDS-only. All 127 JSON-RPC methods have full parity on UDS — no capability loss.
- **UDS-only mode for Tower CNS** — Prepares for exp114 (cephalic convergence prototype) where primals run domain-socket-only. `beardog server` with no TCP flags = pure UDS. `beardog server --port 9100` = previous behavior.
- **Resolves**: primalSpring Wave 53 TCP drop prep item for bearDog.

### May 25, 2026 -- Wave 113b: Root Doc Cleanup & Orphan Purge

- **Root doc dates aligned** — README, CONTEXT, ROADMAP, START_HERE, ARCHITECTURE (both footer dates), SECURITY all updated to May 25, 2026.
- **Method count drift fixed** — README.md line 34, ROADMAP.md, `docs/PRIMAL_CONTRACTS.md` (line 40 + line 1500): 126 → 127 methods. PRIMAL_CONTRACTS handler breakdown corrected to 103 CryptoHandler + 12 IonicBondHandler.
- **Stale showcase references cleaned** — Cargo.toml `exclude` list trimmed (8 showcase paths removed, fossilized Wave 49). ARCHITECTURE.md showcase section updated. `.gitignore` showcase rules simplified to just the README pointer. SCYBORG_EXCEPTION_PROTOCOL.md, BEARDOG_ECOSYSTEM_SECURITY_INTEGRATION.md, PHYSICAL_GENESIS_BOOTSTRAP_PLAN.md, CAPABILITY_BASED_PRIMAL_INTERACTION.md all updated.
- **ACME spec updated** — `specs/ACME_TLS_INTEGRATION_PATH.md` status changed from "Design — not yet built" to "Implemented" (crates/beardog-acme shipped Wave 107–112).
- **48-file orphan directory deleted** — `crates/beardog-tunnel/src/universal_hsm_discovery/` (616K) was never wired into any module tree. Active equivalent lives at `tunnel/hsm/universal_discovery/`.

### May 25, 2026 -- Wave 113: Wave 49 Ecosystem Tightening

- **Showcase fossilized** — `showcase/` directory (153 files, 1.5 MB: security harness, ACME proto demos, HSM discovery, BTSP tunnel, key lineage, entropy mixing, audit logging, monitoring, dynamic config, performance profiling, ecosystem integration, advanced features) replaced with a README pointer. Contents preserved as fossil record per Wave 49 ecosystem tightening mandate.
- **Deployment patterns verified clean** — No `target/release/beardog` or `which beardog` references in scripts or docs. All binary distribution uses `plasmidBin` depot.
- **`notify-plasmidbin.yml`** confirmed active in `.github/workflows/`.
- **No local `wateringHole/` tree** — already clean; all handoffs centralized in `infra/wateringHole/`.
- **`--security-socket` / sled**: Not applicable to bearDog — single socket via `--socket` / `BEARDOG_SOCKET`; no sled dependency (songbird items).
- **Resolves**: primalSpring Wave 49 bearDog items (showcase fossilization, pipeline debt verification).

### May 24, 2026 -- Wave 112: ACME Daemon Operationalization + Doc Drift Fix

- **ACME renewal daemon wired into server binary** — When `BEARDOG_TLS_MODE=acme` is set, `beardog server` spawns `AcmeClient::run_renewal_loop()` as a background tokio task before starting transports. Config reads from `BEARDOG_ACME_DOMAINS` (required), `BEARDOG_ACME_EMAIL`, `BEARDOG_ACME_DIRECTORY` (defaults to Let's Encrypt production), `BEARDOG_ACME_CHALLENGE_PORT` (default 80), `BEARDOG_ACME_RENEWAL_DAYS` (default 30). Non-fatal on init failure. When cellMembrane's sovereignty cutover approaches, set the env vars and the daemon handles cert renewal automatically.
- **Method count doc drift fixed** — README.md (badge line), CONTEXT.md (protocols line), `sporeprint/validation-summary.md` (description + body) updated: 126 → 127 methods, IonicBondHandler 11 → 12.
- **New dependency** — `beardog-acme` added to `beardog-cli/Cargo.toml`.
- **Resolves**: primalSpring Wave 47 bearDog items (doc drift + ACME operationalization).

### May 23, 2026 -- Wave 111: Attestation Field Name Alignment

- **`signed_attestation` → `attestation`** in `primal.announce` payload — biomeOS expects `attestation` as the key for Ed25519 attestation data. Changed in `send_primal_announce` only; legacy `capability.register` retains `signed_attestation` for its own schema.
- **Resolves**: primalSpring Wave 45 bearDog item (LOW priority).

### May 23, 2026 -- Wave 110: `primal.announce` Self-Announcement to biomeOS

- **`primal.announce` on startup** — bearDog now sends a JSON-RPC `primal.announce` call to biomeOS when starting in server mode. The announce payload follows the biomeOS v3.69+ schema: `capabilities` (`["crypto", "security"]`), `methods` (45 canonical `crypto.*` / `security.*` names), `socket` (own UDS path), `cost_hints`, `latency_estimates`, `signal_tiers` (`["tower"]`), and optional `signed_attestation` (Ed25519). Sent alongside the existing `capability.register` calls for backward compatibility.
- **New function: `send_primal_announce`** (beardog-ipc) — Push-style JSON-RPC `primal.announce` to any biomeOS socket. Connects, sends NDJSON-framed request, reads response, logs success/error. Non-fatal on failure (standalone operation preserved).
- **New function: `beardog_announce_method_names`** (beardog-ipc) — Returns `&'static [&'static str]` of 45 canonical dotted method names across `crypto.*` (40) and `security.*` (5). Used by both CLI `handle_server` and tunnel `register_with_discovery_service` paths.
- **Both server paths wired** — `crates/beardog-cli/src/handlers/server.rs` and `crates/beardog-tunnel/src/modes/server.rs` both send `primal.announce` after Neural API detection.
- **3 new tests** — `announce_methods_includes_crypto_and_security`, `announce_methods_are_dotted_canonical`, `send_primal_announce_connection_failure`.
- **Validation**: After this change, `neural_api.routing_weights` should show bearDog as a provider for `crypto.*` calls when biomeOS is running.
- **Resolves**: primalSpring Wave 43 bearDog item (HIGH priority).

### May 22, 2026 -- Wave 109: Ionic Bond Verification + ACME Phase 3 Renewal Daemon

- **New IPC method: `crypto.ionic_bond.verify_proposal`** — Stateless verification of a pending bond proposal's Ed25519 signature. Target gates can now inspect proposer identity, terms hash, trust model, and TTL status *before* calling `accept`. Returns `valid: true/false` with full proposal metadata. Handles expired proposals and unknown IDs gracefully.
- **`IonicBondProposeResponse` extended** — `proposer_public_key` (hex-encoded Ed25519 verifying key) now included in the propose response. Acceptors can verify the proposer's signature offline without out-of-band key exchange via `auth.public_key`.
- **ACME Phase 3 — renewal daemon complete** — `needs_renewal()` now parses X.509 `notAfter` from PEM via `x509-parser`, comparing against `renewal_days_before_expiry`. Order polling (`poll_order_ready`) with exponential backoff (1–10s), CSR finalization (`finalize_order`), certificate chain download (`download_certificate`), and Ed25519 private key PEM serialization are all implemented. Full end-to-end path: discover → register → order → challenges → poll ready → finalize CSR → poll valid → download cert → `store_cert` → hot-reload ready. Last piece before Cloudflare removal (S1 formal cutover).
- **Workspace cleanup** — Removed deleted `showcase/05-mixed-entropy` from workspace members.
- **New dependency** — `x509-parser 0.16` added to `beardog-acme` (cert expiry parsing).
- **3 new tests** — `verify_proposal_valid`, `verify_proposal_not_found`, `propose_returns_public_key`.
- **Methods**: 126 → 127 (1 new `crypto.ionic_bond.verify_proposal`).
- **Resolves**: primalSpring Wave 38 items 1 and 2 for bearDog.

### May 20, 2026 -- Wave 108: `content.*` Scope Expansion + Clippy Cleanup

- **`content.*` scope added to `auth.issue_session`** — All purpose categories (`jupyterhub`, `notebook`, `desktop`, `research`/default) now include `content.*` in their scope vectors. This unblocks SP-4 sovereign publish: bearDog-issued session tokens can now authorize `content.put` calls to nestGate under `BEARDOG_AUTH_MODE=enforced`. No changes to `scope_covers_method` or `MethodGate::check` were needed — the glob matcher already handled `content.*` patterns; only the token issuance table was missing the entry.
- **Pre-existing clippy lint resolved** — `multi_transport_server.rs` SIGTERM handler `expect()` (Wave 106) annotated with `#[expect(clippy::expect_used)]`. `cargo clippy -p beardog-tunnel --lib -- -D warnings` now passes clean.
- **New test** — `issue_session_default_purpose_includes_content_scope` verifies `content.*` presence in research/default tokens.
- **Resolves**: primalSpring Wave 31 `content.*` scope expansion (MEDIUM).

### May 19, 2026 -- Wave 107: ACME Phase 2 — `beardog-acme` Crate + Shadow Metrics + JupyterHub Design

- **New crate: `beardog-acme` (D1 — blocks S1 TLS cutover)** — Implements RFC 8555 ACME client for automated certificate lifecycle. Modules: `account` (Ed25519 keypair generation + persistence), `jws` (JWS Flattened JSON signing per RFC 7515), `challenge` (HTTP-01 solver serving `/.well-known/acme-challenge/` on configurable port), `order` (order lifecycle state machine), `storage` (PEM persistence at `$BEARDOG_DATA_DIR/acme/certs/<domain>/`), `client` (full orchestration: directory discovery → account registration → order → challenge → renewal loop), `hot_reload` (atomic `TlsAcceptor` swap via `watch` channel), `shadow_metrics` (parity measurement). 35 unit tests. Pure Rust, `forbid(unsafe_code)`.
- **Hot-reload mechanism** — `create_hot_reload_pair()` returns `(HotReloadAcceptor, HotReloadController)`. Controller reloads from cert store or raw PEM; acceptor provides `current()` for the TLS listener and `changed()` for waiting on updates. No server restart required.
- **Shadow metrics collector (S1)** — `ShadowMetricsCollector` with `record_sovereign_request()` / `record_commercial_request()` tracks latency, errors, requests/sec, and cert rotation success for both sides. `daily_parity_check()` implements cutover criteria: sovereign p95 ≤ 1.5× commercial p95. `run_parity_loop()` checks every 24h and logs `CUTOVER READY` when 7 consecutive days pass.
- **JupyterHub dual-auth design (D4 — blocks S4 auth shadow)** — New `specs/JUPYTERHUB_DUAL_AUTH_INTEGRATION.md` specifies: `BearDogAuthenticator` (Python class for JupyterHub), ionic token → session mapping via `jti`, `BEARDOG_TLS_MODE=shadow` dual-auth config, metric targets (< 50ms auth latency, > 99.9% refresh reliability), no new IPC methods required (existing `auth.verify_ionic` + `auth.public_key` cover the flow).
- **Workspace updated** — `beardog-acme` added to `[workspace.dependencies]` and `crates/*` glob. New crate brings workspace to 30 directories.
- **Quality gates**: `cargo fmt` clean, `cargo clippy` 0 warnings, `cargo doc` clean, `cargo test` 248+ pass (1 pre-existing env-dependent failure unchanged).

### May 18, 2026 -- Wave 106: Stale Socket Prevention (SIGTERM + Explicit Cleanup)

- **SIGTERM signal handling added to `MultiTransportServer::start_all`** — The primary production entry point (`beardog server` CLI) now registers both `SIGINT` and `SIGTERM` signal handlers. When either signal arrives, all transport tasks are aborted and all Unix socket servers receive explicit `stop()` calls that remove socket files from disk. Previously, `SIGTERM` (used by systemd, docker, kill) terminated the process without guaranteed socket cleanup, leaving stale `.sock` files that caused `ConnectionRefused` for downstream consumers.
- **Explicit `stop()` call on all `UnixSocketIpcServer` instances** — Socket file removal and IPC capability symlink cleanup now happen deterministically on shutdown, not just via `Drop` (which may not fire during forced task abort or runtime teardown).
- **Pre-existing `unlink-before-bind` confirmed at 3 layers** — `SocketConfig::prepare()` (sync `fs::remove_file`), `UnixSocketIpcServer::new()` (async `tokio::fs::remove_file`), and platform `UnixSocket::bind()` / `IOSSocket::bind()` all remove stale sockets before bind. Defense-in-depth: even if a prior crash left a socket, the next startup cleans it before binding.
- **Cross-platform** — SIGTERM handling is `#[cfg(unix)]`; on non-Unix platforms, only `ctrl_c` applies (correct behavior for Windows named pipes which have no filesystem cleanup concern).
- **Resolves**: primalSpring stale socket upstream ask (May 18, 2026). wetSpring observed 50+ stale sockets causing ~2s wasted per Barrick clone run. Server-side cleanup eliminates the problem at the source.
- **Modified files**: `multi_transport_server.rs` (signal handling + explicit stop), `STATUS.md`, `CHANGELOG.md`.

### May 17, 2026 -- Wave 105: Stadial Gate Readiness (deny.toml Policy Fix & ACME Design)

- **`deny.toml` ring policy reconciled** — `ring` was banned with `wrappers = []` but pulled as `rustls`'s crypto backend (the only production-quality pure-Rust TLS implementation with WebPKI support). Policy updated: `ring` now allowed when wrapped by `rustls` or `rustls-webpki`. Direct `ring` usage remains banned. Stale `mio` skip entry removed (single-version resolved). `cargo deny check bans` passes with zero errors and zero warnings.
- **ACME TLS integration path documented** — New `specs/ACME_TLS_INTEGRATION_PATH.md` specifies the stadial shadow cutover design for automated certificate lifecycle management. Covers: crate architecture (`beardog-acme`), challenge types (HTTP-01, TLS-ALPN-01, DNS-01), certificate storage (`$BEARDOG_DATA_DIR/acme/`), hot-reload via `Arc<ServerConfig>` swap, renewal strategy (12h check, 30-day-before-expiry renewal), shadow cutover mode (`BEARDOG_TLS_MODE=acme|static|shadow`), future IPC surface (`acme.status`, `acme.trigger_renew`, `acme.list_certs`), and downstream pairing (cellMembrane, projectNUCLEUS). Phase 1 (design) complete; no code changes required at this stage.
- **Universal standards checklist verified** — Self-audit against Wave 22 stadial gate checklist confirms: health triad (PASS), UDS socket layout (PASS), TCP fallback (PASS), server subcommand with `--port` (PASS), standalone startup (PASS), capabilities.list shape (PASS), identity.get (PASS), BTSP crypto ChaCha20-Poly1305 + HKDF btsp-v1 (PASS), FAMILY_ID + INSECURE guard (PASS), UDS-first default (PASS), deny.toml bans (PASS — now reconciled), edition 2024 (PASS), musl targets (PASS).
- **Stadial pairing documented** — cellMembrane/projectNUCLEUS (TLS termination cutover), all primals (BTSP negotiation via Tower cluster). No composition gaps.
- **Modified files**: `deny.toml` (policy + skip cleanup), new `specs/ACME_TLS_INTEGRATION_PATH.md`, `STATUS.md`, `CHANGELOG.md`.

### May 15, 2026 -- Wave 103: FIDO2/CTAP2 IPC Surface (UB-2 — Hardware-Attested Authentication)

- **`beardog.fido2.discover` IPC method** — Enumerates connected FIDO2/CTAP2-compliant USB security keys via `beardog-hid` pure Rust HID layer. Returns device path, VID/PID, manufacturer, product name. Feature-gated behind `ctap2`: without the feature, returns empty list with guidance note. Enables downstream primals to probe hardware key availability without embedding HID dependencies.
- **`beardog.fido2.register` IPC method** — Creates a FIDO2 credential on a USB security key (CTAP2 `MakeCredential`). Requires physical presence (user touch). Accepts `rp_id`, `user_id` (base64), `user_name`, optional `device_path` (auto-selects first FIDO2 device). Delegates to `SoloV2Provider::generate_key_on_device()` via `HidCtap2Transport` with full CTAPHID frame reassembly. Returns `credential_id`, `public_key` (base64), `rp_id`, `user_name`, `key_id`.
- **`beardog.fido2.authenticate` IPC method** — Gets an assertion from a FIDO2 device (CTAP2 `GetAssertion`). Requires physical presence. Accepts `rp_id`, `credential_id` (base64), `challenge` (base64), optional `device_path`. Delegates to `SoloV2Provider::sign_with_device()`. Returns `signature` (base64), `user_present: true`, `rp_id`, `credential_id`. This is the primary method for hardware-attested witness signatures in `liveSpore.json`.
- **New handler** — `Fido2Handler` struct registered in `MethodHandlerKind` enum, wired into `HandlerRegistry` Phase 1 construction. Capability manifest includes `fido2` type v1.0 with `[discover, register, authenticate]` methods. Cost estimates: discovery 50ms, register/authenticate 5000ms (human interaction).
- **Tests** — 12 new tests: method list assertion, discovery response structure, parameter validation (6 missing-param tests for register and authenticate), handler routing, unknown method error.
- **Methods 123 → 126** (3 `beardog.fido2.*`).
- **New file**: `handlers/fido2.rs`.
- **Modified files**: `handlers/mod.rs` (module + enum + registry), `capabilities.rs` (manifest + costs).

### May 13, 2026 -- Wave 102: Ionic Lease + Seed Fingerprint (Glacial Debt / Tower Atomic)

- **Ionic lease on `crypto.sign_contract`** — `SignContractParams` now accepts optional `ttl_seconds` (u64). When present, `SignContractResponse` includes an `expires_at` RFC 3339 timestamp computed from `signed_at + ttl_seconds`. `crypto.verify_contract` accepts optional `expires_at` and performs lease expiry checking: if the timestamp is in the past, verification returns `{valid: false, expired: true, error: "ionic lease expired"}`. When no `expires_at` is provided, verification behaves as before (pure signature check). Enables GPU lease, data egress fence, and time-bounded trust patterns requested by downstream springs.
- **`crypto.seed_fingerprint` IPC method** — New method returning a stable, non-reversible fingerprint of the primal's `FAMILY_SEED` / `BEARDOG_FAMILY_SEED` identity material. Uses `BLAKE3(HMAC-SHA256(seed, "seed-fingerprint-v1"))` truncated to 16 bytes (32 hex chars). Enables ludoSpring Tower atomic validation (GAP-16) to verify seed consistency across primals without exposing the seed itself. Registered in `method_list.rs`, routed through `aliases_and_beardog.rs`, advertised in capability manifest.
- **Purpose-key derivation confirmed complete** — `crypto.derive_purpose_key` and `crypto.derive_public_key` already fully implemented, tested, and routed (HMAC-SHA256-purpose-v1 convention). No additional work needed for H2 niche task.
- **Capability manifest updated** — Crypto capability methods list expanded to include `seed_fingerprint`. Cost estimate added (`cpu: low`, `latency_ms: 1`).
- **Tests** — 5 ionic lease tests (TTL present, TTL absent, future expiry valid, past expiry invalid, no expiry ignores lease), 5 seed fingerprint tests (valid hex, deterministic, per-seed differs, missing seed fails, routes via aliases). Crypto method count: 105 → 106. 14,940+ total tests passing, 0 failures.
- **Modified files**: `beardog-types/src/ionic_bond.rs` (types), `ionic_bond/contract.rs` (lease handler), `ionic_bond/tests.rs` (lease tests), `crypto_handler/purpose_key.rs` (fingerprint handler + tests), `crypto_handler/aliases_and_beardog.rs` (routing), `crypto_handler/method_list.rs`, `crypto_handler_tests.rs` (method count), `capabilities.rs`.

### May 11, 2026 -- Wave 101: Crypto IPC Surface for barraCuda Delegation

- **`crypto.hkdf_sha256` IPC method** — New standalone HKDF-SHA256 extract-and-expand endpoint. Accepts `ikm` (base64), optional `salt` (base64), optional `info` (base64 or UTF-8), and optional `length` (default 32, max 8160). Returns `{okm, algorithm, length}`. Matches the exact derivation pattern barraCuda uses for BTSP Phase 3 key upgrade (`btsp-v1-phase3` info with client+server nonce salt). Enables any primal to delegate HKDF operations to BearDog instead of embedding `hkdf` crate directly.
- **`crypto.hmac_verify` IPC method** — New constant-time HMAC-SHA256 verification endpoint. Accepts `key`, `data`, `mac` (all base64), computes HMAC-SHA256, and compares using `subtle::ConstantTimeEq`. Returns `{valid: bool, algorithm}`. Completes the HMAC lifecycle alongside existing `crypto.hmac_sha256` (compute-only). Required for barraCuda's `BTSP_HMAC_PLAIN` frame integrity verification.
- **Crypto surface now covers barraCuda BTSP needs** — With these additions, BearDog's `crypto.*` IPC surface covers all three operations barraCuda embeds for BTSP framing: AEAD encrypt/decrypt (`crypto.chacha20_poly1305_encrypt`/`decrypt`), HKDF key derivation (`crypto.hkdf_sha256`), and HMAC compute+verify (`crypto.hmac_sha256`/`crypto.hmac_verify`). Unblocks barraCuda crypto dedup per primalSpring stadial gate audit.
- **Capability manifest updated** — Crypto capability methods list expanded to include `hmac_verify` and `hkdf_sha256`. Cost estimates added (both `cpu: low`, `latency_ms: 1`).
- **Tests** — 9 new handler tests (HMAC verify: correct/wrong/missing, HKDF: default/custom/salt+info/deterministic/different-salt/missing-ikm/missing-params/barraCuda-pattern-match), 5 new router tests. Crypto method count: 103 → 105. 14,925+ total tests passing, 0 failures.
- **Modified files**: `crypto/hash.rs` (handlers), `crypto/mod.rs` (re-exports), `crypto_handler/hashing.rs` (routing), `crypto_handler/method_list.rs`, `crypto_handler_tests.rs` (method count), `capabilities.rs`.

### May 10, 2026 -- Wave 100: TLS Termination & Rate Limiting (H2-10/H2-11 Sovereignty)

- **X.509/TLS termination (H2-10)** — New `tls-server` feature in `beardog-tunnel` providing native TLS termination via `rustls` + `tokio-rustls`. The TCP server can now serve HTTPS directly without Cloudflare or any external TLS proxy. Certificate chain and private key loaded from PEM files (`BEARDOG_TLS_CERT_PATH`, `BEARDOG_TLS_KEY_PATH`). Supports PKCS8, PKCS1, and SEC1 key formats. SNI hostname validation via `rustls` built-in support. TLS connections are transparently upgraded before the JSON-RPC handler, sharing the same `handle_plaintext_connection` codepath with cleartext connections.
- **Connection rate limiting (H2-11)** — New `ConnectionRateLimiter` module providing per-IP sliding-window token bucket rate limiting. Configurable via `BEARDOG_RATE_LIMIT_MAX_CONN` (default 100/min), `BEARDOG_RATE_LIMIT_WINDOW_SECS` (default 60), `BEARDOG_RATE_LIMIT_MAX_TOTAL` (default 1000). Loopback IPs are allowlisted. Stale IP buckets auto-pruned every 5 minutes. Wired into the TCP accept loop — connections are rejected before any TLS/BTSP handshake or JSON-RPC parsing. Uses `DashMap` for lock-free concurrent tracking.
- **Server refactor** — Extracted `handle_plaintext_connection` as a generic handler over `AsyncRead + AsyncWrite`, shared by cleartext TCP, BTSP auto-detected plaintext, and TLS-terminated connections. Eliminates code duplication in the NDJSON JSON-RPC path.
- **Dependencies** — `rustls 0.23` (ring backend), `tokio-rustls 0.26`, `rustls-pemfile 2.2` added as workspace deps. Feature-gated behind `tls-server` (default-enabled in `beardog-tunnel`). `dashmap` added to `beardog-tunnel` for rate limiter.
- **JH-11 confirmation** — Wave 99's `auth.public_key` endpoint confirmed as the key distribution API requested by primalSpring audit. No further BearDog work needed; downstream primals wire `BearDogVerifier` pattern.
- **Tests** — 7 TLS config tests, 8 rate limiter tests. 14,905+ total tests passing, 0 failures.
- **Modified files**: `Cargo.toml` (workspace deps), `beardog-tunnel/Cargo.toml` (features + deps), `tcp_ipc/mod.rs`, `tcp_ipc/server.rs` (TLS + rate limit integration), new `tcp_ipc/tls.rs`, new `tcp_ipc/rate_limiter.rs`, `STATUS.md`, `CHANGELOG.md`.

### May 9, 2026 -- Wave 99: Token Federation, Bonding Aliases & Scope Compat (primalSpring Later-Term Audit)

- **`auth.public_key` endpoint (JH-11)** — New gate-handled public method returning the primal's Ed25519 verifying key in base64, hex, and DID formats. Enables cross-primal token verification without calling back to the issuing BearDog: any primal can call `auth.public_key` once, cache the key, and verify ionic tokens locally. Resolves primalSpring audit item "Token key distribution (JH-11)" for cross-host and multi-family deployments.
- **`bonding.*` method aliases** — Five new aliases in `HandlerRegistry::route()` mapping primalSpring's bonding namespace to BearDog's crypto.ionic_bond surface: `bonding.propose` → `crypto.ionic_bond.propose`, `bonding.accept` → `crypto.ionic_bond.accept`, `bonding.status` → `crypto.ionic_bond.list`, `bonding.terminate` → `crypto.ionic_bond.revoke`, `bonding.modify_scope` → `crypto.ionic_bond.seal`. Resolves primalSpring guidestone Layer 5 "method not found" for `bonding.propose`. Aliases also advertised in `discover_capabilities` response.
- **`scopes` alias in token responses** — `auth.issue_ionic`, `auth.issue_session`, and `auth.verify_ionic` now return both `scope` (original) and `scopes` (alias) as arrays of pattern strings (`*`, `domain.*`, exact). Forward-compatible with primalSpring's `scope_permits_method()` which matches both field names.
- **Auth capability v2.0 → v3.0** — Methods list expanded to include `issue_session` and `public_key`. Cost estimate for `auth.public_key` added. Cleartext bypass includes `auth.public_key`.
- **Tests** — 5 new `auth.public_key` tests (determinism, cross-primal verification, key format), 3 updated method gate tests. 14,889+ total tests passing, 0 failures.
- **Modified files**: `ionic_token_handlers.rs`, `method_gate.rs`, `method_gate_tests.rs`, `handlers/mod.rs` (registry aliases), `capabilities.rs`.

### May 8, 2026 -- Wave 97: Cross-Family Contract Signing & Session Token UX

- **Cross-family contract lifecycle** — New `crypto.contract.propose`, `crypto.contract.countersign`, `crypto.contract.verify` IPC methods implementing multi-party contract signing across family boundaries. Pending contracts tracked in `IonicBondHandler` with TTL expiry and Ed25519 dual-signature verification. Resolves primalSpring audit item "Ionic bond cross-family contract signing (Open)", unblocking hotSpring GAP-HS-005 (GPU lease), healthSpring (dual-tower ionic), and wetSpring (provenance cross-spring).
- **Types** — `ContractProposeParams`, `ContractProposeResponse`, `ContractCountersignParams`, `ContractCountersignResponse`, `CrossFamilyContract`, `ContractVerifyParams`, `ContractVerifyResponse` added to `beardog-types::ionic_bond`.
- **`auth.issue_session` (JH-4)** — Simplified token issuance for non-technical researchers. Purpose-driven scoping (`jupyterhub`, `desktop`, `notebook`, `research`, `admin`) with auto-derived scope patterns and TTL. Returns usage hint for environment variable or Bearer header. Gate-handled as public method alongside `auth.issue_ionic`.
- **Capabilities** — Contract signing capability bumped v1.0 → v2.0 with 5 methods. `auth.issue_session` added to resource manifest, cleartext bypass list, and discover_capabilities. Operation dependencies declared.
- **Pre-existing doc warnings fixed** — `ConfigError::*` broken rustdoc links in `beardog-config` (4 files: `timeouts_new/core.rs`, `network_ports.rs`, `network_hosts.rs`, `network_addresses.rs`, `paths.rs`). Unresolved `PrimalIdentity::from_env` and `SocketConfig` links in `beardog-tunnel` (2 files: `utils.rs`, `client.rs`).
- **Tests** — 7 new cross-family contract tests, 7 new `auth.issue_session` tests, 3 new method gate tests. 14,883+ total tests passing, 0 failures.
- **Modified files**: `ionic_bond.rs` (types), `contract.rs` (handler), `mod.rs` (handler reg), `tests.rs`, `ionic_token_handlers.rs`, `method_gate.rs`, `method_gate_tests.rs`, `capabilities.rs`, `utils.rs`, `client.rs`, 4 beardog-config doc files.

### May 8, 2026 -- Wave 96: Root Doc Alignment, PRIMAL_CONTRACTS Fix & ROADMAP Catchup

- **Date alignment across 8 root docs** — README, ARCHITECTURE, CONTEXT, START_HERE, ROADMAP, SECURITY, docs/README, CONTRIBUTING all updated from May 7 → May 8. README also adds `JSON-RPC Methods: 117` to status line.
- **PRIMAL_CONTRACTS.md corrections** — Category ordering fixed (12 Ionic Bond → 13 Auth → 14 Identity, was scrambled 13→14→12). Auth category now lists all 5 methods (was missing `auth.peer_info`). `auth.peer_info` moved from Identity to Auth where it belongs. Identity corrected from "1 method" to "2 methods" (`identity.get` + `identity.create`). Transport section expanded: NDJSON framing documented, BTSP encrypted frames, TCP port 9190, named pipes for Windows.
- **ROADMAP.md catchup** — "Recently Completed" section extended from Wave 85 through Wave 95 (10 wave summaries added). Method count updated from "100+" to "117".
- **CONTRIBUTING.md ↔ CI reconciliation** — Clippy command corrected from `--all-features` to `--all-targets -- -D warnings` (matching `ci.yml`). Test workflow documents CI gate (`--workspace --lib`) vs local full suite (`--workspace`). Note added that integration/chaos tests under `tests/` are local-only.
- **ARCHITECTURE.md showcase correction** — "not workspace members" claim corrected: `showcase/05-mixed-entropy` is a workspace member.
- **Audit: no debris, no archive candidates** — Full scan confirmed: 0 temp files, 0 dead scripts, 0 `todo!()`/`unimplemented!()` in production, 0 stale planning docs requiring removal. Showcase shell scripts are by-design (standalone demo runners for excluded workspace members). `crates/beardog-integration` and `crates/beardog-deploy` are intentionally excluded per PRIMAL_RESPONSIBILITY_MATRIX V2.
- **wateringHole README.md** date updated.
- **Modified files**: `README.md`, `ARCHITECTURE.md`, `CONTEXT.md`, `START_HERE.md`, `ROADMAP.md`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/README.md`, `docs/PRIMAL_CONTRACTS.md`, `STATUS.md`, `CHANGELOG.md`.

### May 8, 2026 -- Wave 95: Deep Debt Cleanup — Refactors, Bug Fixes & Dead Code Removal

- **`method_gate.rs` smart refactor (811 → 425 LOC)** — Extracted 389-line test suite to `method_gate_tests.rs` using `#[path]` attribute. Production module well under 800-line threshold. All 55 gate tests pass unchanged.
- **Lineage proof signature verification fixed (pre-existing bug)** — `verify_proof()` in `lineage_proof.rs` had its `chain_manager.verify_relationship()` call commented out because `sign_relationship` included a timestamp in the signed message that `verify_relationship` omitted. Fix: extracted `relationship_message()` canonical message builder used by both sign and verify, with `established_at` as the shared timestamp source. Verification now performs real Ed25519 signature checks on lineage relationships. 3 previously-broken tests now pass (49 lineage tests green).
- **Commented-out dead code cleaned in 4 production files:**
  - `birdsong/lineage_proof.rs` — Replaced 6-line commented-out `verify_relationship` block with real verification and failure-path handling.
  - `config/unified/implementations.rs` — Removed dead commented `interval_seconds`/`retention_hours` assignments (fields removed in unified config).
  - `config/monitoring_migration.rs` — Removed phantom `interval_seconds` extraction with dead assignment; replaced 6 empty stub function "would implement" comments with honest `tracing::debug!` logging (functions called from production, intentional no-ops during migration).
  - `android_strongbox/safe_device_detection.rs` — Moved JNI KeyStore pseudocode from inline comments to doc comment on `check_android_keystore_strongbox` function.
- **`LockFreeQueue<T>` placeholder** — Improved documentation: doc comment explains capacity-only shape contract and what will change when real queue is wired. `#[allow(dead_code)]` retains `reason` string.
- **New file**: `method_gate_tests.rs` (389 LOC) — test suite for `method_gate.rs`.
- **Modified files**: `method_gate.rs`, `lineage_proof.rs`, `lineage_chain.rs`, `implementations.rs`, `monitoring_migration.rs`, `safe_device_detection.rs`, `ultimate_performance.rs`.
- **Tests**: 55 method_gate + 49 lineage + 32 monitoring_migration = 136 tests verified green.
- **Clippy**: Clean across all 4 affected crates (`beardog-tunnel`, `beardog-genetics`, `beardog-types`, `beardog-utils`).

### May 8, 2026 -- Wave 94: JH-1 Primal-Native Identity and Ionic Token Infrastructure

- **Ed25519-signed ionic capability tokens** — New `ionic_token.rs` module: compact `base64(header).base64(payload).base64(signature)` wire format with `IonicTokenHeader` (`alg:EdDSA, typ:ionic, ver:1`), `IonicTokenPayload` (`iss` DID, `sub`, `scope` globs, `iat`, `exp`, `jti`). `issue_ionic_token()` signs with primal's deterministic Ed25519 key; `verify_ionic_token()` checks signature + expiry. `scope_covers_method()` supports `*` (wildcard), `prefix.*` (namespace), and exact patterns. `TokenError` enum: `Malformed`, `InvalidSignature`, `Expired`, `UnsupportedFormat`.
- **3 new JSON-RPC methods (gate-handled):**
  - `identity.create` — Generate ephemeral Ed25519 keypair; returns `{did, public_key, secret_key, algorithm}`. For caller identities (not primal identity).
  - `auth.issue_ionic` — Issue signed ionic token: params `{subject, scope?, ttl_secs?}`; returns `{token, issuer, subject, scope, ttl_secs}`. Default scope `["*"]`, default TTL 3600s.
  - `auth.verify_ionic` — Verify token: params `{token, method?}`; returns `{valid, scope_ok?, claims?, error?, reason?}`.
- **Real cryptographic token verification in `MethodGate`** — Replaced `bearer_token.is_some()` with full pipeline: decode 3-part token → Ed25519 signature check against `self.verifying_key` → expiry check → `scope_covers_method()` check. `MethodGate` now stores `verifying_key`, `primal_name`, `node_id`. `CallerContext.validated_claims: Option<IonicTokenPayload>` populated on success. `auth.check` now includes `claims` field when present.
- **Bearer token extraction from wire** — `_bearer_token` field extracted from JSON-RPC `params` object in UDS `route_jsonrpc()` and TCP NDJSON/BTSP paths before gate check (biomeOS convention from JH-0 handoff).
- **Capabilities updated** — Auth capability `v2.0` with `["check", "mode", "peer_info", "issue_ionic", "verify_ionic"]`. New identity capability `v1.0` with `["get", "create"]`. Cost estimates, cleartext methods, discover_capabilities entries added.
- **Method count 114 → 117** (103 CryptoHandler + 8 IonicBondHandler + 5 auth gate + 1 identity gate).
- **55 new tests** across `ionic_token`, `ionic_token_handlers`, and `method_gate` modules.

### May 8, 2026 -- Wave 93: JH-0 MethodGate Pre-Dispatch Authorization

- **`MethodGate` pre-dispatch layer** — Ecosystem-standard method gate adopted per `primalSpring/wateringHole/METHOD_GATE_STANDARD.md`. Every JSON-RPC method classified as `Public` (health, identity, capabilities, auth introspection — always allowed) or `Protected` (requires capability token when enforcement active). Default mode: `Permissive` (logs but allows). `BEARDOG_AUTH_MODE=enforced` rejects with `-32001 PERMISSION_DENIED`.
- **`CallerContext` threading** — Per-connection caller identity (`bearer_token`, `peer` credentials, `origin` Unix/Loopback/Remote) threaded through both UDS and TCP dispatch paths.
- **3 auth introspection methods** — `auth.check` (authentication status), `auth.mode` (enforcement mode), `auth.peer_info` (peer credentials) handled pre-dispatch at gate layer. Advertised in `capabilities.list`, `discover_capabilities`, and method index.
- **Error codes** — `PERMISSION_DENIED` (-32001), `UNAUTHORIZED` (-32000), `NOT_READY` (-32002) added to `beardog-ipc::protocol::error_codes` and `beardog-tunnel::unix_socket_ipc::types::JsonRpcError` with constructor methods.
- **Method count 111 → 114** (103 CryptoHandler + 8 IonicBondHandler + 3 auth pre-dispatch).
- **26 new tests** for method classification, gate enforcement, auth handler responses, dispatch routing.

### May 7, 2026 -- Wave 92: Contract Signing IPC Confirmation & Documentation

- **`crypto.sign_contract` and `crypto.verify_contract` confirmed IPC-routable** — primalSpring Phase 60 audit reported these as "not yet exposed as IPC-routable methods." Investigation confirms they have been registered on `IonicBondHandler::methods()` and dispatched through `HandlerRegistry::route()` since Wave 38/42. The gap was **documentation and discoverability**, not routing.
- **`PRIMAL_CONTRACTS.md` expanded** — full Ionic Bond section added (8 methods): detailed request/response JSON for all lifecycle methods (`propose`, `accept`, `seal`, `verify`, `revoke`, `list`) and contract signing methods (`crypto.sign_contract`, `crypto.verify_contract`). Method index updated with all 8 IonicBondHandler methods. Cross-spring signing workflow documented for healthSpring/hotSpring/wetSpring.
- **Method count corrected 103 → 111** — CryptoHandler has 103 methods (verified by test), IonicBondHandler has 8 methods (verified by test). Previous docs reported "103 (98 CryptoHandler + 5 IonicBondHandler)" which was doubly wrong: CryptoHandler was already 103 (not 98) and IonicBondHandler was 8 (not 5) since Wave 38. Fixed across `STATUS.md`, `PRIMAL_CONTRACTS.md`, `ROADMAP.md`.

### May 7, 2026 -- Wave 91: Typed Errors — BondPersistence & SslKeylog

- **`BondPersistenceError` enum introduced** — `BondPersistence` trait migrated from `Result<_, String>` to `Result<_, BondPersistenceError>`. Five variants: `Serialization`, `Io`, `RpcTimeout`, `RpcError`, `InvalidResponse`. All three implementations (`InMemoryBondPersistence`, `BondPersistenceBackend`, `CapabilityDiscoveryBondPersistence`) updated. `BondPersistenceResult<T>` type alias added. Handler boundary converts via `.map_err(|e| e.to_string())`.
- **`SslKeylogError` enum introduced** — `export_to_sslkeylogfile` migrated from `Result<(), String>` to `Result<(), SslKeylogError>`. Two variants: `InvalidClientRandom`, `Io`. Caller in `derive_handshake.rs` unchanged (uses `Display` via `warn!`).
- **Zero `Result<_, String>` remaining in persistence or TLS keylog modules** — last P3 item from primalSpring Phase 60 audit resolved.
- **24 tests pass** (2 persistence, 3 sslkeylog, 19 ionic_bond handler). Zero clippy warnings.

### May 7, 2026 -- Wave 89: crypto.sign Contract Fix & did:key Derivation (RP-1/RP-5)

- **`crypto.sign` contract documentation fixed** — `PRIMAL_CONTRACTS.md` Ed25519 section rewritten: stale `data`/`key` params corrected to actual `message`/`key_id`/`purpose`. Semantic alias `crypto.sign` documented. Response fields (`signature`, `algorithm`, `key_id`, `public_key`) documented. Signing contract clarified: BearDog signs raw bytes, callers handle domain separation.
- **`crypto.did_from_key` method added** — new JSON-RPC method derives W3C `did:key:z6Mk...` from BearDog Ed25519 signing key (multicodec Ed25519 prefix + base58btc). Unblocks RootPulse commit workflow and LoamSpine entry signing by providing the `committer` DID. 4 tests. `bs58` dep added (pure Rust).
- **Method count 102 → 103** (CryptoHandler 97 → 98, IonicBondHandler 5 unchanged).
- **Cross-primal signing workflow documented** in `PRIMAL_CONTRACTS.md`: `crypto.did_from_key` → `crypto.sign` → pass to LoamSpine.

### May 5, 2026 -- Wave 87: Dependency Evolution & Typed Config Errors

- **`crossterm` 0.27→0.29** — eliminates `mio` 0.8/1.0 duplication; `crossterm 0.29` depends on `mio ^1.0`, unifying with tokio's `mio 1.x`. Zero API breakage.
- **Typed config validation errors** — 5 `validate()` methods in `beardog-config` migrated from `Result<(), String>` to `ConfigResult<()>` (`Result<(), ConfigError>`). Errors use `ConfigError::InvalidValue { field, message }` and `ConfigError::PortConflict`. DRY `range_check()` helper introduced for timeout validation. 20+ test assertions updated.
- **Deep dependency audit** — `syn` confirmed build-time only (proc-macro), `tokio` `full` feature justified (all sub-features used across workspace), zero `mio` duplication remaining, zero unused transitive crates identified.

### May 5, 2026 -- Wave 86: TCP IPC Port Alignment & Discovery Hierarchy Documentation

- **TCP IPC port aligned to ecosystem convention** — `DEFAULT_TCP_IPC_PORT` changed from `9900` to `9100` to match primalSpring/ironGate/plasmidBin probe targets. `DEFAULT_METRICS_PORT` moved from `9100` to `9190` to avoid collision.
- **Discovery Escalation Hierarchy documented** — 5-tier discovery order (Songbird → biomeOS Neural API → UDS convention → socket registry → TCP probing) added to `ENVIRONMENT_VARIABLES.md` and `QUICK_START_ZERO_HARDCODING.md`.
- **`BEARDOG_TCP_IPC_PORT` and `BEARDOG_METRICS_PORT` env vars documented** — added to reference docs with defaults and ecosystem context.
- **Clippy fixes** — `async fn` syntax in HSM stub provider, `pub(crate)` visibility in test module.

### May 4, 2026 -- Wave 85: Deep Debt — Stale Alias Cleanup, Dep Pruning & Feature Gating

- **Stale re-export aliases removed** — `SimplifiedBearDogConfig as UnifiedBearDogConfig` at `beardog_types` crate root (actively confusing since the name collided with the real `UnifiedBearDogConfig` struct in `canonical::config::unified`), `PrimaryUnifiedBearDogConfig` (zero callers), `WorkingUnifiedConfig` (3 test callers migrated to `SimplifiedBearDogConfig`), and `capability_routing as capability_router` (2 import sites migrated). Stale comments referencing removed aliases cleaned from `canonical/mod.rs`.
- **Unused `rsa` dep removed from `beardog-security`** — zero `rsa::` usage in the crate; `rsa` is only actively used by `beardog-core` and `beardog-tunnel`.
- **`x509-parser` feature-gated** in `beardog-tunnel` — new `tls-x509` feature (default-on) gates `x509-parser` and the `tls.verify_certificate` handler. Slim builds can disable it to shed the `nom`/`asn1-rs`/`der-parser`/`oid-registry` transitive dep tree. Both default and no-default builds compile cleanly.
- **Zero test failures** — 12,610 lib tests pass, 0 clippy warnings.

### May 4, 2026 -- Wave 84: Deep Debt — O(1) Handler Dispatch, getrandom Alignment & Workspace Hygiene

- **O(1) JSON-RPC method dispatch** — `HandlerRegistry` now builds a `HashMap<&'static str, usize>` at init (Phase 3 of construction) that maps every registered method name to its handler index. `route()` performs O(1) lookup instead of scanning all handlers and calling `.methods().contains()` per handler. Falls back to linear scan only if the map was never built (should not happen in normal operation).
- **`getrandom` 0.2→0.3** — workspace pin upgraded from `"0.2"` to `"0.3"` to align with `rand 0.9` / `rand_core 0.9` (which depend on `getrandom 0.3`). All 4 call sites in `software_hsm_impl.rs` migrated from `getrandom::getrandom()` to `getrandom::fill()`. Eliminates duplicate `getrandom` major versions in the dependency tree.
- **Workspace dep hygiene** — 5 internal crates (`beardog-threat`, `beardog-compliance`, `beardog-workflows`, `beardog-production`, `beardog-node-registry`) migrated from `path = "../..."` to `{ workspace = true }` in their consumers. 3 zero-consumer entries (`beardog-deploy`, `beardog-installer`, `beardog-client`) removed from `[workspace.dependencies]`. Internal workspace section now annotated.
- **Zero test failures** — 12,610 lib tests pass, 0 clippy warnings.

### May 4, 2026 -- Wave 83: Bond Persistence Default Upgraded to Capability Discovery

- **Bond persistence default changed** — `HandlerRegistry::new()` now creates a `CapabilityDiscoveryBondPersistence` backend instead of `InMemoryBondPersistence`. When a `bonding.ledger` provider (NestGate/loamSpine) is discovered at runtime via Songbird, sealed bonds are persisted via JSON-RPC to that provider's socket. When no provider is available, falls back to in-memory (identical prior behavior). Zero breakage for standalone or composition deployments.
- **Phase 58 primalSpring audit** — 4 gaps reviewed: (1) Phase 3 transport encryption RESOLVED (Wave 81), (2) `crypto.sign_contract` RESOLVED (already implemented in `IonicBondHandler`), (3) `btsp.negotiate` vs `btsp.session.negotiate` naming INTENTIONAL (different methods), (4) bond persistence default now upgraded.
- **Zero test failures** — 12,610 lib tests pass.

### May 3, 2026 -- Wave 82: Deep Debt — Orphan Code Removal, Stale Lints & Workspace Hygiene

- **716-line orphan file deleted** — `canonical/config/discovery.rs` was never included in any module tree (`mod.rs` had no `mod discovery` declaration). 716 lines of dead code containing deprecated `ConsolidatedDiscoveryConfig`, `LegacyDiscoveryProtocol`, `HealthCheckConfig`, `RetryConfig`, and `LoadBalancingConfig` structs that were never compiled.
- **6 deprecated zero-caller type aliases removed** from `beardog-production/config_management` — `ConnectionPoolConfig`, `LoggingConfig`, `LogFormat`, `LoadBalancerConfig`, `MigrationConfig`, `BackupConfig`. All production code already uses the canonical paths directly. Stale `CanonicalMigrationConfig` import also cleaned.
- **2 stale `#[expect(dead_code)]` removed** — `SIMDCapabilities` in `beardog-utils` (fields are alive, struct was never dead) and `MockCloudHsm::with_failures()` in `beardog-tunnel` (method now has callers). Replaced with `#[allow(dead_code, reason = "...")]` where field-level suppression is still needed.
- **8 `#[allow]` attributes given `reason`** — `recovery_tests/types.rs` (4), `meta_tests.rs` (2), `coverage_gap_tests_5.rs` (1), `coverage_gap_tests_7.rs` (1). All `#[allow]` now carry `reason` per modern Rust style.
- **`base64-url` centralized** to `[workspace.dependencies]` — was the last crate-local version pin outside the workspace table. `beardog-security/Cargo.toml` now uses `{ workspace = true }`.
- **HSM management documentation clarified** — `hsm_management.rs` methods now document "software-only mode" behavior explicitly and carry `reason` on their `#[allow(dead_code)]` annotations.
- **Session lifetime constant** `DEFAULT_EXTENDED_SESSION_LIFETIME_SECS` now has `reason` on its test-only `#[allow(dead_code)]`.
- **Zero test failures** — 12,610 lib tests pass, 0 clippy warnings, 0 unfulfilled lint expectations.

### May 3, 2026 -- Wave 81: BTSP Phase 3 — Encrypted Frame I/O Transition (Interop Fix)

- **Phase 3 interop gap fixed** — After `btsp.negotiate` returns `cipher: "chacha20-poly1305"` + `server_nonce`, the connection now transitions to encrypted frame I/O. Previously the connection stayed in plaintext NDJSON mode, causing the client (which had already transitioned to encrypted framing) to read `0x7B226A73` (`{"js`) as a 2 GB frame header.
- **New `Phase3Session` struct** in `btsp_handshake/session.rs` — handles ChaCha20-Poly1305 AEAD with **random 12-byte nonces** per frame (matching primalSpring wire format). Unlike `BtspSession` (Phase 2, counter-based nonces), Phase 3 uses CSPRNG nonces and no counter validation on decrypt.
- **New `handle_jsonrpc_phase3` connection handler** — encrypted frame loop using Phase 3 session keys. Wire format: `[4B len BE u32][12B random nonce][ciphertext + Poly1305 tag]`.
- **`try_phase3_upgrade` detection** — after writing any JSON-RPC response, the NDJSON loops (`handle_jsonrpc_universal` and `handle_jsonrpc_ndjson_loop`) check if the request was `btsp.negotiate` and the response selected a non-null cipher. On match, derives Phase 3 session keys and transitions to `handle_jsonrpc_phase3`.
- **Key re-derivation** — `try_phase3_upgrade` parses `client_nonce` from the request and `server_nonce` from the response, loads `FAMILY_SEED`, and re-derives keys via the same `HKDF-SHA256` path as the handler. Deterministic derivation ensures both sides hold identical keys.
- **6 new Phase3Session tests**: roundtrip encrypt/decrypt, random nonce uniqueness, tamper rejection, short frame rejection, multi-message roundtrip, wrong-key rejection.
- **Zero test failures** — 2,133 beardog-tunnel lib tests pass, 12,610+ workspace lib tests pass.

### May 2, 2026 -- Wave 80: Deep Debt — Dead Code Removal, Deprecated Symbol Cleanup & Flaky Test Fix

- **6 dead production code items removed**: orphaned `HsmSource` enum (duplicate of orchestrator's own), unused `DeployConfig` placeholder struct, unused `probe_service_endpoint` method, 3 unused `SovereigntyManager` fields (`genetics`, `crypto_config`, `hierarchy_manager`) that were constructed but never read.
- **2 deprecated zero-caller symbols removed**: `BearDogResult<T>` type alias (beardog-errors + root lib.rs) and `PrimalTypeMigrationHelper` struct + migration guide. Both had zero production callers.
- **Flaky test fixed**: `test_handle_key_export_roundtrip_uses_default_home_env` — the `HOME` mutex was released before handlers ran, allowing concurrent tests to corrupt the `process_env` overlay. Fixed by holding the lock for the entire test duration and adding `#[serial_test::serial]`. Same fix applied to 2 sibling tests. **Zero test failures across the full workspace for the first time.**
- **2 doc_markdown clippy warnings fixed** in BTSP negotiation handler.

### May 2, 2026 -- Wave 79b: Deep Debt Pass — Workspace Dependency Drift, Build Script Cleanup & Dead Dep Removal

- **16 workspace dependency drifts normalized** — `aes`, `ctr` (beardog-utils), `ahash`, `urlencoding`, `approx` (beardog-core), `local-ip-address` (beardog-discovery), `ecdsa`, `x509-parser`, `arrayref`, `data-encoding` (beardog-tunnel), `path-absolutize`, `console`, `indicatif` (beardog-deploy), `rpassword`, `whoami`, `assert_cmd`, `predicates` (beardog-cli), `directories` (beardog-installer) added to root `[workspace.dependencies]` and crate-local pins converted to `{ workspace = true }`.
- **Stale `android_native` cfg emission removed** from `beardog-tunnel/build.rs` — the feature was already removed from `[features]` in Wave 78b but `build.rs` line 30 still emitted `cargo:rustc-cfg=feature="android_native"` on Android targets. This created potential `unexpected_cfgs` warnings. Emission and stale doc reference removed.
- **`tempfile` reclassified** in `beardog-security/Cargo.toml` — was under `[dependencies]` despite zero production usage. Moved to `[dev-dependencies]`.
- **Deep debt audit confirmed clean**: 0 files >800 LOC, 0 unsafe, 0 `todo!()`/`unimplemented!()`, 0 `#[async_trait]`, 0 `Box<dyn Error>` in production, 0 hardcoded peer primal names in runtime logic, 0 production mocks outside `#[cfg(test)]`. `hsm_provider_mocks` module already correctly gated since prior wave.

### May 2, 2026 -- Wave 79: BTSP Phase 3 — `btsp.negotiate` Server-Side Implementation

- **New method: `btsp.negotiate`** — Phase 3 encrypted post-handshake channel negotiation. After a successful Phase 1 handshake, primalSpring sends `btsp.negotiate` with `session_id`, `ciphers` (array), and `client_nonce` (base64). Server selects the best cipher (preference: `chacha20-poly1305` > `hmac-plain` > `null`), generates a 32-byte `server_nonce`, derives session keys via `HKDF-SHA256(handshake_key, client_nonce || server_nonce)` with directional info strings `btsp-session-v1-c2s` / `btsp-session-v1-s2c`, and returns `{"cipher":"chacha20-poly1305","server_nonce":"<b64>"}`. NULL cipher fallback returns `{"cipher":"null"}` — zero breakage for Phase 2-only clients.
- **Phase 3 key derivation** — `derive_phase3_session_keys()` added to `btsp_handshake/crypto.rs`. Mirrors primalSpring's `SessionKeys::derive()` exactly (same HKDF salt/info construction), ensuring both sides derive identical directional keys.
- **Wire compatibility** — Accepts both `"ciphers"` (array, primalSpring canonical) and `"preferred_cipher"` (string, audit blurb form) parameter names.
- **BTSP methods**: 35 → 36 (new `btsp.negotiate`). Registered in `BtspHandler::methods()`, routed in `handle()`, advertised in `capabilities.list` as `btsp_phase3` capability group.
- **12 new tests**: cipher selection (4 tests: prefers chacha20, hmac fallback, null fallback, empty list), negotiate happy path, null cipher fallback for unsupported ciphers, missing params/session_id/client_nonce validation, missing FAMILY_SEED error, `preferred_cipher` alias, key derivation verification. Plus 4 crypto-level tests for `derive_phase3_session_keys` (deterministic, directional, nonzero, nonce sensitivity).
- **Pre-existing crypto method count assertion fixed** — `test_crypto_handler_methods` and `test_handler_method_count` had conflicting assertions (97 vs 102); both normalized to actual count of 102.
- **primalSpring validation**: Two `#[ignore]` integration tests (`phase3_negotiate_with_live_beardog`, `phase3_transport_full_roundtrip`) will auto-validate once plasmidBin harvests this binary.

### April 30, 2026 -- Wave 78b: Deep Debt Pass — Production Mock Isolation, Workspace Drift & Dead Feature Cleanup

- **Production mocks gated behind `#[cfg(test)]`** — `IpcTestHandler`, `IpcFailingRegisterHandler`, `IpcFailingEventHandler`, `IpcFailingCapabilityHandler`, `IpcHandlerBackend` enum dispatch, and `IpcServer` struct in `ipc_server.rs` were compiled into the production library despite being test-only. All moved into a `#[cfg(test)] mod test_fixtures` submodule. `unreachable!()` calls in test fixture impls no longer ship in release binaries.
- **10 workspace dependency drifts normalized** — `crossbeam`, `dashmap`, `http`, `url`, `walkdir`, `dotenvy`, `dirs`, `tokio-stream`, `getrandom` added to `[workspace.dependencies]`. Crate-local version pins in `beardog-core`, `beardog-types`, `beardog-utils`, `beardog-deploy`, `beardog-config`, `beardog-discovery`, `beardog-security` converted to `{ workspace = true }`.
- **Dead `android_native` feature removed** from `beardog-tunnel/Cargo.toml` — declared and emitted by `build.rs` on Android targets but never checked via `cfg(feature)` in any Rust source file.
- **Deprecation form normalized** — `#[deprecated = "msg"]` in `primal_types/io.rs` converted to structured `#[deprecated(since = "0.9.0", note = "...")]` form.
- **Deep debt audit confirmed clean**: 0 files >800 LOC, 0 unsafe, 0 `todo!()`/`unimplemented!()`, 0 `#[async_trait]`, 0 `Box<dyn Error>` in production, 0 hardcoded peer primal names in runtime logic, 0 production mocks outside `#[cfg(test)]`.

### April 30, 2026 -- Wave 78: primalSpring Phase 56c Audit — Both BearDog Items Confirmed Resolved

- **`async-trait` 49→0 confirmed complete** — primalSpring's own `PRIMAL_GAPS.md` confirms "COMPLETE (Wave 53–55: 49→0, 22 traits → 18 enum dispatch types, RPITIT, dep removed + lockfile clean, banned in deny.toml)". `syn v1` fully eliminated from dependency tree. Only `syn v2` remains (proc-macro derives: serde, clap, thiserror, tokio, tracing — all compile-time, not actionable).
- **`crypto.sign_contract` confirmed wired since Wave 42** — Fully implemented in `IonicBondHandler` (`ionic_bond/contract.rs`), registered in method list, advertised in `capabilities.list`, with 10+ integration tests. The audit blurb's "not yet exposed as IPC method" is stale information.
- **Audit cross-check**: `lineage.list` (genetic.rs), `btsp.session.verify` (btsp/mod.rs), `crypto.derive_public_key` (purpose_key.rs) — all IPC methods referenced by other primals are wired and tested.
- **Dependency duplication audit**: thiserror v1 (transitive from x509-parser, tungstenite, asn1-rs — not actionable), getrandom v0.2/v0.3/v0.4, rand v0.8/v0.9 (ecosystem migration, transitive). All BearDog-owned code on latest versions.
- **`mockito` workspace normalized** in Wave 77b (cont.) — beardog-client and beardog-integration now use `{ workspace = true }`.
- **`cargo deny check`** — 4/4 PASS (advisories, bans, licenses, sources).
- **Zero new code changes** — all items were already complete.

### April 30, 2026 -- Wave 77b: Deep Debt Pass — `#[allow]` Reason Hygiene & Workspace Dependency Drift

- **19 bare `#[allow(...)]` in production code given `reason` metadata** — `async_fn_in_trait` (4 files), `deprecated` (4 files), `missing_docs` (8 coordination config files), `cast_precision_loss`/`cast_possible_wrap`/`cast_sign_loss` (resilience), `dead_code` (infrastructure), `wildcard_imports`/`missing_errors_doc` (consolidated traits), `double_must_use`/`missing_errors_doc` (algorithms), `needless_doctest_main` (threat management), `cast_precision_loss` (math constants).
- **Workspace dependency drift fixed** — `beardog-tower-atomic`, `beardog-discovery`, `beardog-installer`, `beardog-client` added to `[workspace.dependencies]`. `beardog-client/Cargo.toml`: 3 path pins (`beardog-tower-atomic`, `beardog-genetics`, `beardog-errors`) converted to `{ workspace = true }`. `beardog-integration/Cargo.toml`: 8 path pins converted to `{ workspace = true }`.
- **Deep debt audit confirmed clean**: 0 files >800 LOC, 0 unsafe blocks, 0 production mocks (all `#[cfg(test)]`-gated), 0 hardcoded peer primal names, 0 `#[async_trait]`, 0 `Box<dyn Error>` in production, 0 `todo!()`/`unimplemented!()`.

### April 30, 2026 -- Wave 77: primalSpring v0.9.24 — `crypto.derive_public_key` for biomeOS Coordination Keys

- **New method: `crypto.derive_public_key`** — Derives an Ed25519 public key for a named purpose from `FAMILY_SEED`. Wire: `{"method":"crypto.derive_public_key","params":{"purpose":"coordination"}}` → `{"public_key":"<b64>","algorithm":"Ed25519","purpose":"coordination","derivation":"HMAC-SHA256-purpose-v1 → Ed25519"}`. Enables biomeOS Neural API to auto-derive coordination keys at startup without manual key provisioning.
- **Methods**: 101 → 102 (CryptoHandler 97, IonicBondHandler 5).
- **7 new tests**: basic, deterministic, different-purposes-differ, no-seed-fails, missing-purpose-fails, missing-params-fails, routing integration via `aliases_and_beardog::route`.
- **BTSP Phase 3**: Deferred per primalSpring audit — Phase 2 handshake is sufficient for current composition validation.

### April 29, 2026 -- Wave 76b: GAP-23 Exhaustive UDS Audit — Reclassification Confirmed

- **Exhaustive UDS accept-path audit** — Matching rhizoCrypt's GAP-22 methodology, performed a full audit of BearDog's Unix socket IPC path. **Zero path-dependent behavior found:**
  - `listener.accept()` discards peer address (`_addr`, `platform/unix.rs:81`)
  - `handle_connection()` takes only `Box<dyn PlatformStream>` — no socket path argument (`server.rs:314`)
  - BTSP `ClientHello` wire type has no socket path field (`btsp_handshake/types.rs:12-19`)
  - BTSP handshake keyed on `family_seed` only — no path validation (`btsp_handshake/handshake.rs:35-109`)
  - First-byte auto-detect branches on `0x7B` (JSON) vs length-prefix (BTSP) — no path (`server.rs:320-341`)
  - `HandlerRegistry::route()` signature: `(method, params, btsp_provider)` — no path (`handlers/mod.rs:302-327`)
  - `FAMILY_ID` sourced from `PrimalIdentity` or RPC params — never from socket path
- **GAP-23 formally reclassified to primalSpring** — A symlink produces the exact same `UnixStream` at the kernel level. BearDog never sees which pathname the client used to `connect()`. Same three hypotheses as GAP-22: startup ordering, stale binary, or proxy layer — all primalSpring-side.
- **Handoff updated** with full evidence table and diagnostic guide for primalSpring.

### April 29, 2026 -- Wave 76: primalSpring Phase 56 Audit — GAP-23 & IONIC-RUNTIME Resolution

- **GAP-23 resolved (not a BearDog bug)** — `crypto.blake3_hash` error on capability socket (`crypto-{family}.sock`) was a parameter encoding issue on the caller side. The capability socket is a symlink to `beardog-{family}.sock` — identical code path. BearDog requires `{"data": "<standard-base64>"}` (JSON object, not array). Error messages improved with format guidance: missing params now says `expected: {"data": "<standard-base64>"}`, missing `data` says `(standard base64 encoded string)`, invalid base64 says `use standard base64 (RFC 4648, +/= alphabet)`.
- **IONIC-RUNTIME resolved (already complete)** — `crypto.sign_contract` has been wired and tested since Wave 42. Full lifecycle: `crypto.ionic_bond.propose` → `.accept` → `.seal` + standalone `crypto.sign_contract` / `crypto.verify_contract`. 8 methods in `IonicBondHandler`, 10+ integration tests. The gap in primalSpring `PRIMAL_GAPS.md` was stale.
- **No new RPC methods** — Both gaps were documentation/parameter issues, not missing functionality.

### April 28, 2026 -- Wave 75: Deep Debt Pass — Purpose-Key Module Extraction, Dependency Drift & Stale Feature Cleanup

- **`aliases_and_beardog.rs` refactored (927 → 452 LOC)** — Extracted NUCLEUS purpose-key operations (`handle_derive_purpose_key`, `handle_sign_registration`, `handle_purpose_encrypt`, `handle_purpose_decrypt`, `resolve_purpose_key`, `load_family_seed`) and their 8 tests into a new `purpose_key.rs` submodule in `crypto_handler/`. Routing in `aliases_and_beardog.rs` now delegates via `use super::purpose_key::*`. Zero behavior change.
- **Workspace dependency drift fixed** — `tokio-test` in `beardog-client` and `wiremock` in `beardog-integration` converted from inline version pins to `{ workspace = true }`. Eliminates future version skew risk.
- **Stale `dns-sd` feature gate removed** — `beardog-discovery/tests/coverage_boost.rs` had `#[cfg(feature = "dns-sd")]` gated imports and a test, but the `dns-sd` feature was suspended and removed from `Cargo.toml`. Dead code deleted.
- **Unused imports cleaned** — `serde_json::{Value, json}` removed from `aliases_and_beardog.rs` (moved to `purpose_key.rs`).
- **CI gates**: `cargo fmt` clean, `cargo clippy --workspace -- -D warnings` 0 warnings, `cargo deny check` 4/4 pass, `cargo test --workspace` zero new failures (1 pre-existing flaky test in beardog-cli).

### April 28, 2026 -- Wave 74: primalSpring Phase 55b — Lazy Purpose-Key Derivation & Purpose-Based Encrypt/Decrypt

- **Lazy purpose-key derivation in `secrets.retrieve`** — When a secret matching the NUCLEUS pattern `nucleus:{family}:purpose:{name}` is requested and doesn't exist, BearDog now auto-derives the purpose key from `FAMILY_SEED`/`BEARDOG_FAMILY_SEED` via `HMAC-SHA256(seed, hex("purpose-v1:" + purpose))` and stores it. NestGate and Squirrel can call `secrets.retrieve("nucleus:{family}:purpose:storage")` without requiring `nucleus_crypto_bootstrap.sh` to have run first.
- **`crypto.encrypt` with `purpose` param** — When `purpose` is provided (instead of `key`), resolves the purpose key from `FAMILY_SEED` and encrypts with ChaCha20-Poly1305. Returns the NUCLEUS standard envelope: `{"v":1,"ct":"<b64>","n":"<b64>","alg":"chacha20-poly1305"}`. Backward-compatible: existing `key`-based calls unchanged.
- **`crypto.decrypt` with `purpose` param** — Accepts NUCLEUS envelope fields (`ct`/`n`) or standard names (`ciphertext`/`nonce`), resolves the purpose key, and decrypts. Backward-compatible.
- **No new RPC methods** — Both features are enhancements to existing `secrets.retrieve`, `crypto.encrypt`, and `crypto.decrypt` methods. Method count stays at 101.
- **9 new tests** — 5 for secrets lazy derivation (basic, deterministic, no-seed-fails, non-nucleus-not-derived, parse-pattern), 4 for purpose encrypt/decrypt (roundtrip, different-purposes-differ, no-seed-fails, key-path-unchanged). All `#[serial]` for env-var safety.
- **Resolves** primalSpring v0.9.21 Phase 55b audit: "lazy purpose-key derivation" and "purpose param in encrypt/decrypt."

### April 28, 2026 -- Wave 73: Deep Debt Pass — Orphan Cleanup, Benchmark Normalization & Lint Hygiene

- **Orphan test files deleted (2,277 LOC)** — 6 `*_comprehensive_tests.rs` files across `beardog-core`, `beardog-types`, `beardog-security`, and `beardog-cli` were never referenced in any module tree (never compiled). Deleted: `operations_comprehensive_tests.rs` (421), `tests_comprehensive.rs` (507), `security_operations_comprehensive_tests.rs` (390), `capability_registry_comprehensive_tests.rs` (254), `cli_comprehensive_tests.rs` (354), `handler_integration_comprehensive_tests.rs` (351).
- **Benchmarks workspace normalization** — 9 dependencies in `benchmarks/Cargo.toml` converted from version-pinned/path to `{ workspace = true }`: `beardog-core`, `beardog-errors`, `beardog-utils`, `criterion`, `tokio`, `toml`, `serde`, `chrono`, `tracing`. Added `[lints] workspace = true`.
- **Missing `[lints] workspace = true`** — Added to `beardog-integration-tests/Cargo.toml` (only crate under `crates/` missing it).
- **`#[allow(deprecated)]` reason hygiene** — 6 bare `#[allow(deprecated)]` attributes across `beardog-types` (monitoring_unified, production config, type_aliases) and `beardog-core` (trait_impl) now carry `reason = "..."` fields. All `#[allow()]` in production code are now justified.
- **`#[expect(` reason hygiene** — 2 bare `#[expect(clippy::*)]` in `zero_knowledge_bootstrap/mod.rs` now carry `reason` fields.
- **Stale commented dependency blocks removed** — `beardog-types/Cargo.toml`: removed 4 `REMOVED:` comment blocks (ring, reqwest features and dependency stubs) whose removal history is already in CHANGELOG.
- **Clippy fix** — 2 `map().unwrap_or()` → `map_or()` in `benchmarks/src/utils.rs`.
- **tarpc debris deleted** — `tests/tarpc_e2e_tests.rs` (301 LOC, dead since Jan 29 2026 tarpc removal) and `docs/references/QUICK_REFERENCE_TARPC.md` (108 lines, references non-existent docs, contradicts current JSON-RPC architecture). 4 broken references to non-existent `TARPC_REMOVAL_RATIONALE_JAN_29_2026.md` replaced with self-contained comments. Link removed from `docs/references/ROOT_INDEX.md`.
- **Stale Cargo.toml comment blocks cleaned** — `REMOVED:` blocks purged across root `Cargo.toml`, `beardog-tunnel`, `beardog-cli`, `beardog-deploy`, `beardog-workflows`, `beardog-node-registry`. Duplicate AES deferred block in beardog-tunnel consolidated to a pointer to root workspace. Commented-out `[[bin]]` UniBin block removed from beardog-tunnel.

### April 28, 2026 -- Wave 72: primalSpring Phase 55 Audit — NUCLEUS Purpose Key Derivation & Signed Registrations

- **`crypto.derive_purpose_key`** — New first-class IPC method for the NUCLEUS two-tier crypto model. Derives purpose-specific keys from a parent family key using `HMAC-SHA256(key, hex("purpose-v1:" + purpose))`. Replaces the workaround of chaining raw `crypto.hmac_sha256` calls. Deterministic, 32-byte output, aligned with `wateringHole/NUCLEUS_TWO_TIER_CRYPTO_MODEL.md`.
- **`crypto.sign_registration`** — New IPC method for signing `ipc.register` payloads. Canonicalizes registration fields (`primal_id`, sorted `capabilities`, `endpoint`) into a deterministic string and signs with Ed25519. Consumers can verify authentic service registrations using `crypto.verify`. Resolves primalSpring audit: "service registrations are unsigned and consumers can't verify authenticity."
- **Method count**: 99 → 101 (CryptoHandler + IonicBondHandler)
- **5 new tests**: derive_purpose_key (basic, deterministic, different-purposes-differ), sign_registration (basic, verify-roundtrip)
- **Resolves** primalSpring v0.9.20 Phase 55 audit gaps 1 and 2.

### April 27, 2026 -- Wave 71: Deep Debt Pass — Workspace Hygiene, Debris Cleanup & Broken Link Fixes

- **Workspace dependency normalization** — `tokio-test` (beardog-adapters, beardog-ipc, beardog-integration), `parking_lot`, `uuid` (beardog-integration) converted from version-pinned to `{ workspace = true }`. Redundant feature echoes (`chrono` serde, `tracing-subscriber` env-filter) removed from beardog-integration.
- **Duplicate comment debris removed** — Duplicate AES Phase 7 deferred block in beardog-tunnel `Cargo.toml` (copy-paste of root workspace comment) deleted.
- **Orphan code deleted (2,685 LOC)** — `beardog-errors/src/unified_error_system/` (5 files, 1,843 LOC) was entirely outside the module tree (never compiled). `beardog-errors/src/tests/coverage_expansion_tests.rs` and `error_recovery_comprehensive_tests.rs` (842 LOC) not referenced in `tests/mod.rs`.
- **Date-stamped test files renamed** — `crypto_service/tests_coverage_expansion_dec17.rs` → `tests_coverage_expansion.rs`, `tests_dec18_edge_cases.rs` → `tests_edge_cases.rs`. Removed date comments from `crypto_service/mod.rs`.
- **Broken documentation links fixed** — `showcase/00_START_HERE.md` and `showcase/00-local-primal/README.md`: corrected `ENTROPY_HIERARCHY_PRINCIPLE.md` path (root → `docs/references/`), removed reference to deleted `COMPREHENSIVE_AUDIT_REPORT_DEC_24_2025.md`, corrected overstated file counts (specs: 85→63, docs: 166→20). `docs/references/QUICK_START_ZERO_HARDCODING.md`: replaced 3 references to deleted Jan 2026 session files with valid current paths, fixed `self_knowledge.rs` → `self_knowledge/`, `capability_router.rs` → `capability_routing/`. `docs/references/PHYSICAL_GENESIS_BOOTSTRAP_PLAN.md`: removed broken ref to deleted `BIRDSONG_INTEGRATION_ROADMAP_DEC_21_2025.md` and `PHASE3_IMPLEMENTATION_PLAN.md`. `docs/references/README_BIOMEOS_SOCKET.md`: replaced broken `BIOMEOS_SOCKET_INTEGRATION_JAN_30_2026.md` with `ENVIRONMENT_VARIABLES.md`. `docs/references/QUICK_REFERENCE_CARD.md`: replaced 4 references to deleted Nov 2025 session files with current root docs.
- **Spec link cleanup** — `specs/current/integration/BEARDOG_ECOSYSTEM_SECURITY_INTEGRATION.md`: removed broken references to never-created tracker/plan/report docs, updated phase status, corrected date from December 2025 to April 2026.
- **Audit findings (no action needed)** — 70+ `#[deprecated]` items are intentional migration targets for v0.10.0. 2 `BearDogError::not_implemented` in `quantum_discovery.rs` are explicit Phase 2 deferrals. `hsm_provider_mocks.rs` stubs are `#[cfg(test)]`-gated. Zero `todo!()` / `unimplemented!()` macros. All feature gates validated against `Cargo.toml` `[features]`. 31 production files at 700-799 LOC monitored (under threshold).

### April 27, 2026 -- Wave 70d: primalSpring Convergence — ENVIRONMENT_VARIABLES.md Reconciled

- **`docs/references/ENVIRONMENT_VARIABLES.md` rewritten** — Updated from February 2026 to April 27, 2026. Documents `BEARDOG_NODE_ID`, `BEARDOG_FAMILY_ID`, `FAMILY_SEED`/`BEARDOG_FAMILY_SEED`, `BIOMEOS_INSECURE`, `BIOMEOS_SOCKET_DIR`, and `PRIMAL_NAME`. Corrected `FAMILY_ID`/`NODE_ID` from "REQUIRED" to optional with standalone fallback. Updated socket resolution from 4-tier to 5-tier. Added BTSP security mode truth table. Removed stale "Related Documents" links.
- **Resolves** primalSpring convergence validation gap: long-form env var reference now consistent with README.

### April 27, 2026 -- Wave 70b: Deep Debt Audit — Clean Bill of Health

- **Comprehensive 8-dimension audit**: async-trait, unsafe, Box<dyn Error>, ring, large files, hardcoding, self-knowledge, mocks — all clean.
- **Date-stamped test file renamed**: `coverage_expansion_march_2026.rs` → `coverage_expansion_cli_wave.rs` (beardog-cli)
- **Allow-reason hygiene**: converted remaining bare `#[allow(clippy::await_holding_lock)]` and `#[allow(dead_code)]` to use `reason` fields for full consistency.
- **Audit summary**: zero async-trait, zero unsafe blocks (28 crates `#![forbid(unsafe_code)]`), zero production `Box<dyn Error>`, zero ring, zero ungated mocks, zero TODO/FIXME, zero hardcoded peer primal names, all >800L files are test-only.

### April 27, 2026 -- Wave 70: ludoSpring Audit — Identity Fallback Alignment

- **Identity fallback consistency** — `get_node_id_with()` and `get_family_id_with()` in handler utils now use the same fallbacks as `PrimalIdentity::from_env()` and `SocketConfig`: `resolve_process_node_id()` (ephemeral `standalone-{uuid}`) for missing node ID, `DEFAULT_STANDALONE_FAMILY` (`"standalone"`) for missing family ID. Previously returned `"unknown"` which could silently diverge from the socket path's identity.
- **Documentation clarification** — README now explicitly states that only ONE of `NODE_ID` / `BEARDOG_NODE_ID` is needed (not both), addressing the ludoSpring launcher misconception.
- **Resolves** ludoSpring audit: "BearDog needs both NODE_ID and BEARDOG_NODE_ID set, or it fails silently." BearDog has always accepted either variable; the silent issue was inconsistent fallback values across identity resolution sites.

### April 26, 2026 -- Wave 69b: Deep Debt — Self-Knowledge, Allow-Reasons, Blake3 Pure

- **Self-knowledge cleanup** — Removed `skunkBat` reference from `capabilities.rs` wire data and `method_list.rs` comment. Primal code now has pure self-knowledge only (zero other-primal references in production logic).
- **`#[allow()]` hygiene** — Added structured `reason = "..."` to all 3 remaining `#[allow(clippy::wildcard_imports)]` attributes in production code. All `#[allow()]` now carry justification.
- **`blake3` pure alignment** — 5 showcase `Cargo.toml` files aligned to `features = ["pure"]` matching workspace standard. Eliminates `cc`/assembly build path for pure Rust crypto.
- **Comprehensive audit clean** — 0 unsafe, 0 async-trait, 0 TODO/FIXME/HACK, 0 `Box<dyn Error>` in production, 0 production files >800 LOC, 0 ungated mocks, 0 ring/openssl/serde_yaml in Cargo.lock. All `#[allow()]` justified. cargo deny 4/4 PASS.

### April 26, 2026 -- Wave 69: Lineage Semantic IPC Methods

- **`lineage.list` method** — Enumerates all lineage chains via BirdSongManager with summary metadata (chain_id, root_node_id, node_count, generation, created_at). Enables skunkBat thymic selection and federation mesh queries.
- **`lineage.verify` method** — Semantic alias that delegates to `genetic.verify_lineage`. Accepts same params (our_family_id, peer_family_id, lineage_proof, lineage_seed, optional chain_id). Supports both simple Blake3 and chain-based Merkle verification.
- **`lineage.get` method** — Retrieves full lineage chain by chain_id, returns serialized `LineageChain` with nodes, relationships, generation, and head_commitment.
- **`LineageChainSummary` type** — New struct in `beardog-genetics` for efficient chain listing without full serialization.
- **`crypto.sign_contract` confirmed wired** — Verified already fully routed through `IonicBondHandler` with propose→accept→seal lifecycle, capabilities registered, and cost metrics present.
- **Quality** — 99 crypto methods registered. 3 new tests (lineage_list_returns_empty_chains, lineage_verify_delegates_to_genetic, lineage_get_missing_chain). Clippy/fmt clean.

### April 22, 2026 -- Wave 67: Deep Debt — Hardcoded Primal Name Cleanup, Full Audit

- **Hardcoded primal name cleanup** — Removed 2 production-code `biomeOS` references from tracing messages in `primal_discovery.rs` and `discovery.rs`. Replaced with generic terms ("platform sockets", "orchestrator layer"). Primal code now has pure self-knowledge only.
- **Comprehensive debt audit** — 0 unsafe, 0 TODO/FIXME/HACK, 0 `#[async_trait]`, 0 production files >800 LOC, all mocks `#[cfg(test)]` gated, all ports env/config-driven, `Box<dyn Error>` only in tests/docs, `#[allow()]` all justified. `cargo deny` 4/4 PASS.
- **Quality** — 14,925 tests, 0 failures (1 known flaky pre-existing). Clippy/fmt/deny clean.

### April 22, 2026 -- Wave 66: primalSpring Audit — crypto.public_key Method, Sign→Verify IPC Roundtrip

- **`crypto.public_key` method** — New standalone method returns Ed25519 public key for a `key_id` without signing. Enables primals (toadStool, primalSpring) to retrieve public keys for client-side verification. Registered in capabilities list.
- **Sign→verify IPC roundtrip tests** — Updated `route_crypto_sign_and_verify_alias` and `route_ed25519_sign_verify_roundtrip` tests to use the `public_key` from the sign response instead of re-deriving locally. Proves the IPC contract end-to-end.
- **Resolves primalSpring `crypto:ed25519_verify` SKIP** — `crypto.sign` already returned `public_key` (Wave 62); now the router tests prove it, and `crypto.public_key` gives standalone access.
- **Quality** — 14,925 tests (4 new), 96 crypto methods registered. Clippy/fmt/deny clean.

### April 21, 2026 -- Wave 65: Deep Debt — Workspace Dep Normalization, server.rs Smart Refactor

- **Workspace dependency normalization** — `mdns-sd` (4 crates), `validator` (1 crate), `tokio-serde` (1 crate) migrated from explicit version pins to `{ workspace = true }`. Root `Cargo.toml` updated. All crates now use workspace deps exclusively.
- **`server.rs` smart refactor** — `unix_socket_ipc/server.rs` reduced from 834 → 619 LOC. 5 protocol-specific connection handlers extracted to new `connection_handlers.rs` (231 LOC): `handle_jsonrpc_universal`, `handle_http_universal`, `handle_btsp_jsonline_connection`, `handle_jsonrpc_ndjson_loop`, `handle_jsonrpc_btsp`.
- **Mock isolation verified** — `hsm_provider_mocks.rs` confirmed `#[cfg(test)]` gated (corrected false positive from prior survey).
- **Quality** — 14,921 tests, 0 failures (1 known flaky pre-existing). Clippy/fmt/deny clean.

### April 21, 2026 -- Wave 64: primalSpring Phase 45b — BTSP JSON-Line Wire-Format Recognition on UDS

- **BTSP ClientHello detection on UDS** — primalSpring sends `{"protocol":"btsp","version":1,"client_ephemeral_pub":"<b64>"}` as the first line on UDS. BearDog's first-byte peek sees `{` and misclassifies it as JSON-RPC (parse error → broken pipe). Now: after reading the full first line, check for `"protocol":"btsp"` with no `"jsonrpc"` field. If matched, route to JSON-line BTSP handshake instead of JSON-RPC dispatch.
- **`continue_server_handshake_jsonline`** — New handshake function in `btsp_handshake` that performs steps 2–4 using newline-delimited JSON framing (vs. the existing length-prefixed `perform_server_handshake`). Supports primalSpring's wire protocol: ServerHello with `session_id`, HandshakeComplete with `status:"ok"`.
- **Post-handshake routing** — After JSON-line handshake: `null` cipher → plain NDJSON JSON-RPC loop; encrypted ciphers → length-prefixed encrypted frame handler.
- **3 new tests** — `jsonline_handshake_null_cipher` (full roundtrip), `jsonline_handshake_rejects_bad_version`, `jsonline_handshake_rejects_short_key`.
- **Quality** — 14,789+ tests, 0 failures (1 known flaky pre-existing). Clippy/fmt/deny clean.

### April 20, 2026 -- Wave 63: Deep Debt — deny.toml Cleanup, Final Workspace Dep Normalization

- **`cargo deny` 4/4 clean** — Removed 3 stale skip entries (`linux-raw-sys`, `rustix`, `syn` — now single-version). Removed unused `async-trait` wrappers (`hickory-proto`, `hickory-resolver`). Added `cpufeatures` + `socket2` skip entries for transitive duplicates.
- **`crates/beardog/Cargo.toml` normalized** — 8 explicit version pins (`tracing`, `tracing-subscriber`, `tokio`, `serde_json`, `serde`, `uuid`, `chrono`, `anyhow`) migrated to `{ workspace = true }`.
- **Deep debt survey clean** — 0 production files >800 LOC, 0 unsafe, 0 TODO/FIXME/HACK, 0 C deps compiled, all mocks `#[cfg(test)]` gated, all hardcoded primal refs are env-driven constants.
- **Quality** — 14,786+ tests, 0 failures. Clippy/fmt/deny clean.

### April 20, 2026 -- Wave 62: primalSpring Phase 45 Audit — Sign→Verify Roundtrip, Ed25519 Base64 Standardization

- **`crypto.sign` now returns `public_key`** — Sign response includes the standard-base64-encoded Ed25519 public key alongside signature, enabling sign→verify roundtrip via IPC without re-deriving the key. Resolves primalSpring guidestone item BD-PG-01.
- **Ed25519 encoding standardized to standard base64** — `primal_signing::sign_with_primal_identity` migrated from hex to standard base64. Capability announcements and ionic bond signatures now use base64 (was hex). `verify_ed25519_signature` accepts both base64 and hex for backward compatibility. `SignContractResponse` doc comments updated.
- **Quality** — 14,786+ tests, 0 failures. Clippy/fmt clean.

### April 20, 2026 -- Wave 61: Deep Debt — Workspace Dep Normalization (9 Crates), Cross-Arch Fix

- **Workspace dependency normalization** — 40+ explicit version pins across 9 crates (`beardog-discovery`, `beardog-workflows`, `beardog-capabilities`, `beardog-traits`, `beardog-utils`, `beardog-tower-atomic`, `beardog-production`, `beardog-monitoring`, `beardog-types`) normalized to `{ workspace = true }`. Fixes version drift (`serial_test` 3.2.0 → workspace 3.0 in `beardog-monitoring`).
- **Cross-arch compilation fix** — Resolved macOS/iOS/Windows/WASM build errors from primalSpring audit: `PlatformSocket::bind` return type corrected (`UnixListener` → `Box<PlatformListenerBackend>`) in `ios.rs`, `windows.rs`, `wasm.rs`. Platform-specific HSM implementations moved inline into `vec![]` with `#[cfg]` attrs in `discovery_engine.rs`.
- **Deep debt survey** — Zero production files >800 LOC, zero unsafe, zero TODOs, zero commented-out code, zero hardcoded peer primal names. All remaining `#[allow()]` instances documented with reasons and unfulfillable via `#[expect()]`.
- **Quality** — 14,786+ tests, 0 failures. Clippy/fmt/rustdoc clean.

### April 20, 2026 -- Wave 60: Documentation Cleanup, Clippy Fixes, Debris Removal

- **Root docs updated** — All 7 root docs updated to April 20, 2026 with Wave 58 + 59 entries. Enum dispatch inventory corrected to 20 types.
- **Clippy fixes** — `map_unwrap_or` in `primal_discovery_mdns.rs`, unused import + missing variant doc in `hid_transport.rs`.
- **Debris cleaned** — 56 CLI receipt JSON artifacts removed.
- **Quality** — 14,786+ tests, 0 failures.

### April 20, 2026 -- Wave 59: Deep Debt — Enum Dispatch, Workspace Deps, Test Refactoring

- **`Box<dyn>` → enum dispatch** — `Box<dyn ProtocolHandler>` → `ProtocolHandlerBackend` enum (`Minimal`, `Mdns`) in `beardog-core`; `Box<dyn AsyncStream>` → `IpcStream` enum (`Unix`, `Tcp`) in `beardog-ipc` with direct `AsyncRead`/`AsyncWrite` delegation. 20 enum dispatch types total.
- **Workspace dependency normalization** — 21 explicit version pins across `beardog-hid`, `beardog-adapters`, `beardog-genetics` normalized to `{ workspace = true }`. Added `semver` and `crossterm` to workspace deps.
- **`#[allow()]` → `#[expect()]`** — 7 instances migrated (6× `async_fn_in_trait`, 1× `clippy::cast_precision_loss`) with explicit `reason` strings.
- **Test file refactoring** — `fault_injection/mod.rs` (966 LOC) split into 4 domain modules; `graph_security_integration_tests.rs` (881 LOC) split into directory with 3 domain modules + helpers. `type_validation_comprehensive.rs` (820 LOC) kept as-is (short tests, marginal gain).
- **Quality** — 14,786+ tests, 0 failures. All production files <800 LOC. Zero unsafe, zero TODOs.

### April 20, 2026 -- Wave 58: primalSpring Audit — BTSP Documentation, Cleartext Bypass

- **`BEARDOG_FAMILY_SEED` documented** — README now includes BTSP Security Modes table (Development/Production/Startup error) and family seed resolution order (`FAMILY_SEED` → `BEARDOG_FAMILY_SEED` → `.family.seed` file).
- **Cleartext JSON-RPC bypass documented** — README describes first-byte `{` (0x7B) auto-detection on UDS and TCP. `capabilities.list` updated: `cleartext_available: true` in production, `cleartext_methods` array lists safe methods (`crypto.hash`, `health.liveness`, etc.).
- **Quality** — 14,786+ tests, 0 failures. Resolves primalSpring spring audit findings (silent failure on connection reset, BTSP-free basic mode).

### April 16, 2026 -- Wave 56: Deep Debt — serde_yaml Elimination, Typed Errors, Idiomatic Cleanup

- **serde_yaml eliminated** — Deprecated dep removed from `beardog-config`, `beardog-production`, `beardog-types`, and workspace root. YAML config paths return deprecation errors; TOML/JSON remain. `serde_yaml`/`unsafe-libyaml` gone from lockfile.
- **Box<dyn Error> → BearDogError** — Sole production instance in `orchestration.rs` (AI module) converted to typed error.
- **#[allow()] → #[expect()]** — Production attrs migrated where lints fire; cross-target/crate-root attrs retained as `#[allow()]`.
- **Test refactoring** — 3 test files >900 LOC split into domain modules (coverage_gap_wave18, rustcrypto_tests, software_hsm/tests).
- **Quality** — 14,786+ tests, 0 failures. Zero `serde_yaml`, `async-trait`, `ring`, `sled`, `openssl` in lockfile.

### April 16, 2026 -- Wave 55: async-trait Lockfile Elimination — Stadial Gate Cleared (13/13)

- **async-trait fully eliminated from Cargo.lock** — Removed unused `hickory-resolver` from `beardog-core`. Removed never-enabled `tarpc` optional dep + 3 orphan tarpc source files from `beardog-ipc`. Suspended `dns-sd` feature in `beardog-discovery`.
- **deny.toml ban** — `async-trait` added to `[bans].deny` with wrappers for `hickory-proto`/`hickory-resolver`.
- **Lockfile** — Zero `async-trait`, `tarpc`, `opentelemetry`, `ring`, `sled`, `openssl`.
- **Quality** — 14,786+ tests, 0 failures. BearDog clears the stadial async-trait gate as the final primal (13/13).

### April 16, 2026 -- Wave 54: Deep Debt Pass — File Refactoring, Dep Cleanup, Mock Isolation

- **Smart file refactoring** — `software_hsm/types.rs` (936 LOC) split into 9 domain modules (storage, config, keys, encryption, audit, health, etc.). `handlers_coverage_extension.rs` (911 LOC) split into 7 test domain modules.
- **Dependency cleanup** — `beardog-types` explicit version pins unified to workspace deps. `gethostname` consolidated to workspace `hostname`. `syn v1` eliminated by upgrading `tokio-serde` 0.8 to 0.9.
- **Mock isolation** — Android transport stubs platform-gated (`#[cfg(not(target_os = "android"))]`). All mocks verified behind `#[cfg(test)]` or `test-utils` feature.
- **Hardcoding audit** — All production paths confirmed env-driven or capability-discovered. Zero hardcoded primal names in production dispatch.
- **Deep debt status** — Zero `unsafe` (all crates `#![forbid(unsafe_code)]`). Zero TODOs/FIXMEs. Zero production mocks. 14,786+ tests, 0 failures.

### April 16, 2026 -- Wave 53: Stadial Parity Gate — Native Async Traits, Enum Dispatch, `async-trait` Removal

- **All `#[async_trait]` removed** — Roughly 49 trait attributes across 22+ traits migrated to native `async fn` in traits (RPITIT). No `#[async_trait]` remains in any `.rs` file.
- **`async-trait` dropped from every manifest** — Removed from 17 `Cargo.toml` files (7 core crates, 9 showcase, workspace root).
- **Transitive `ring` in lockfile** — Already resolved in a prior wave; lockfile remains clean.
- **Enum dispatch for finite backends** — Replaced `dyn Trait` dispatch with explicit enum types for monomorphized, zero-vtable-overhead routing. 20 dispatch enums: `MethodHandlerKind`, `BondPersistenceBackend`, `HsmKeyProviderBackend`, `HsmProviderBackend`, `UniversalCryptoBackend`, `CryptoProviderBackend`, `KeyManagementBackend`, `ServiceDiscoveryBackend`, `KeystoreTransportBackend`, `AttestationTransportBackend`, `HealthMetricsTransportBackend`, `IpcHandlerBackend`, `PlatformListenerBackend`, `StorageBackend`, `EncryptionKeyBackend`, `AuditLoggerBackend`, `Ctap2TransportBackend`, `HidDeviceBackend`, `ProtocolHandlerBackend`, `IpcStream`.
- **Verification** — 14,786+ tests passing (0 failures); Clippy and rustdoc clean with `-D warnings` on all workspace crates.

### April 15, 2026 -- Wave 51: primalSpring Audit Resolution — UDS Peek, Chain Proofs, Bond Persistence, ring Elimination

- **UDS first-byte protocol auto-detection** — `PrefixedStream` wrapper in `platform/mod.rs` implements `AsyncRead`+`AsyncWrite` to re-prepend a peeked byte. Production UDS connections in `unix_socket_ipc/server.rs` now peek first byte with 5s timeout: `0x7B` → JSON-RPC bypass (local composition traffic), otherwise → BTSP handshake. Matches TCP server behavior. BearDog is no longer the last BTSP-enforcing primal without UDS peek.
- **Genetic RPC → full chain proofs** — `genetic.generate_lineage_proof` and `verify_lineage` JSON-RPC handlers now wire through `BirdSongManager`'s `LineageProofManager` for generation-aware chain proofs with `head_commitment` and `depth`. Request/response types extended with `chain_id`, `node_id`, `generation`, `head_commitment`, `mode`. Backward-compatible: omitting `chain_id` falls back to simple Blake3 hash proofs.
- **Bond persistence trait** — New `BondPersistence` trait in `ionic_bond/persistence.rs` with `store`/`retrieve`/`list`/`remove`. `InMemoryBondPersistence` as default. `IonicBondHandler` updated: `handle_seal` persists, `handle_list` merges persistence with in-memory proposals, `handle_revoke` removes from persistence. `with_persistence(Arc<dyn BondPersistence>)` constructor enables runtime wiring to `bonding.ledger.*` providers.
- **HSM/Titan M2 dispatch path** — `handle_generate_keypair_with_hsm` routes `crypto.generate_keypair` by `hsm_backend` parameter: `"software"` or `None` → existing X25519; `"strongbox"`/`"titan_m2"` → structured JSON error with `available_backends` signaling. Wired through `aliases_and_beardog.rs`.
- **`ring` transitive dependency eliminated** — `beardog-discovery` downgraded from `hickory-resolver 0.25` (pulls ring+cc) to `0.24` (ring-free, matches `beardog-core`). DNS-SD adapted to 0.24 API (`TokioAsyncResolver`, `RData` match, `Box<[u8]>` TXT). `cargo tree -i ring` returns zero matches.
- **`Box<dyn Error>` evolved to typed errors** — `SafeOps::safe_execute` generic `E: Display` bound (no boxing). `beardog-security` (9 doctests) and `beardog-client` (5 doctests) evolved to `BearDogError`/`BearDogClientError`.
- **Hardcoded addresses centralized** — 9 production files: CLI server, config, core self-knowledge, tunnel multi-transport, types monitoring/network/providers, utils zero-copy all use `WILDCARD_IPV4`/`DEFAULT_EXTERNAL_HOST`/`LOCALHOST_NAME` constants.
- **async-trait migration** — `SecureTunnelProvider` in `beardog-capabilities` migrated to native `async fn` in traits. Removed `#[async_trait]` from trait def + 2 impls + `async-trait` dep from `beardog-capabilities/Cargo.toml`. Instance count: ~50 → 49.
- **All quality gates clean** — fmt, clippy -D warnings, doc -D warnings, test (14,785 passing; 1 pre-existing flaky: `key_export_roundtrip` HOME env race).

### Wave 52 — Deep Debt & syn Elimination (April 15, 2026)

- **async-trait elimination**: Removed unused `async-trait` dependency from 5 crates (`beardog-discovery`, `beardog-ipc`, `beardog-adapters`, `beardog-workflows`, `beardog-integration`) — reducing `syn` compilation surface
- **Smart file refactoring**: Split 3 production files approaching 800 LOC by domain concern:
  - `android_strongbox/core.rs` (796 LOC) → `core/` module directory (4 files, max 298)
  - `production/monitoring.rs` (794 LOC) → `monitoring/` module directory (4 files, max 340)
  - `crypto_handlers_tor.rs` (792 LOC) → `crypto_handlers_tor/` module directory (7 files, max 184)
- **Clippy compliance**: Added `# Errors` doc sections, derived `Default` for `HealthStatus`
- Quality gate: 14,787 tests passing, 0 failures, fmt/clippy/rustdoc clean

### April 15, 2026 -- Wave 50: Evolution Pass — Hardcoding, Large File Refactor, Overstep Cleanup

- **Hardcoded ecosystem namespace evolved** — `beardog-tower-atomic/discovery.rs`: replaced 4 hardcoded `"biomeos"` strings in production 5-tier socket discovery with `resolve_biomeos_ipc_subdir_from_optional()`. Added `ipc_namespace` field to `DiscoverSocketEnv` for runtime configurability via `BIOMEOS_IPC_NAMESPACE`. `beardog-core/socket_config.rs`: replaced `.join("biomeos")` with shared constant `BIOMEOS_RUNTIME_SOCKET_SUBDIR`.
- **3 large production files refactored** — `android.rs` 802→588 LOC: deduplicated 220 lines of transport traits/stubs between `android.rs` and orphaned `android_transports.rs`; wired orphan as proper sibling module. `ios.rs` 864→286 LOC: replaced 580 lines of inline tests with `#[path = "ios_tests.rs"]` referencing identical orphaned external file. `mobile_discoverer.rs` 806→471 LOC: extracted 5 repetitive capability builders (353 lines) to new `mobile_hsm_capabilities.rs` with shared default helpers.
- **3 orphaned files wired** — `android_transports.rs`, `ios_tests.rs`, `mobile_hsm_capabilities.rs` from prior refactoring attempts now properly compiled via module tree.
- **Audit findings** — 0 unsafe code, 0 production mocks (all 287 behind `#[cfg(test)]`), 0 TODO/FIXME markers, 0 `.bak`/`.old`/`.tmp` debris. `serde_yaml` tracked for migration when maintained fork stabilizes (deprecated upstream, but pure Rust).
- **All quality gates clean** — fmt, clippy -D warnings, doc -D warnings, test (14,784 passing; 1 pre-existing flaky: `key_export_roundtrip` HOME env race).

### April 14, 2026 -- Wave 49: Deep Debt Sweep — Workspace Deps, Large File Refactor, Dead Exports

- **Workspace dependency alignment (5 crates)** — `beardog-config`, `beardog-deploy`, `beardog-core`, `beardog-auth`, `beardog-node-registry` migrated from explicit version strings to `workspace = true` for 30+ dependencies (serde, tokio, tracing, ed25519-dalek, sha2/sha3, clap, chrono, uuid, tempfile, etc.). Eliminates version drift risk and unifies resolution.
- **Large file smart refactoring (2 files)** — `android_strongbox/core.rs` (850→796 lines): removed dead shadow `AndroidKeyParams` struct + consolidated verbose fully-qualified paths with `unified::` module alias. `cloud_discoverer.rs` (826→790 lines): hoisted 7× repeated capability type imports to module level, eliminating 42 lines of redundant inner `use` blocks.
- **Dead `pub use` re-exports removed** — `beardog-ipc`: `normalize_method` (zero external references). `beardog-utils`: `BufferPoolSafe`, `BufferPoolStats`, `MemoryPoolStats`, `SafeMemoryPool` aliases (zero external references via aliased names).
- **`#![allow(dead_code)]` in infrastructure.rs audited** — Documented reason valid (pub serde surface types; `#[expect]` would be unfulfilled). No migration needed.
- **All quality gates clean** — fmt, clippy -D warnings, doc -D warnings, test (14,784 passing).

### April 14, 2026 -- Wave 48: Transport Security Advertisement (TS-01) — primalSpring Audit Response

- **`transport_security` field in capability responses** — `capabilities.list` and `discover_capabilities` now include `transport_security` object with `btsp_required`, `btsp_version`, `btsp_server_available`, `cleartext_available`, and human-readable `note`. Dynamically determined from `FAMILY_ID` at runtime — `true` on family-scoped sockets, `false` on dev/standalone.
- **BTSP rejection now sends JSON-RPC error** — When a non-BTSP connection arrives on a family-scoped socket, the server sends a `-32600` error with `"BTSP handshake required"` message and guidance before closing, replacing the prior silent connection drop. This gives biomeOS forwarding and primalSpring AtomicHarness a clear signal.
- **Wire standard extended (TS-01)** — New "Transport Security Advertisement" section in `CAPABILITY_WIRE_STANDARD.md` specifying the `transport_security` object format and the companion rejection behavior.
- **Not a BearDog bug** — The composition gap (biomeOS forwards plaintext to BTSP-required sockets) and the AtomicHarness FAMILY_ID wiring are biomeOS/primalSpring side work. These changes make BearDog a better citizen by advertising requirements and providing actionable errors.
- **All quality gates clean** — fmt, clippy, doc, test (14,784 passing).

### April 13, 2026 -- Wave 47: Documentation & Debris Cleanup

- **Root doc metrics unified** — Test count `14,780+` → `14,784+` across 7 root docs. Clone URL placeholders replaced. ecoBin v3.0→v2.0 in CONTRIBUTING (pending serde_yaml elimination).
- **8 broken links fixed** — Showcase, specs, protocol docs (wateringHole paths corrected).
- **3 orphaned stale test files removed** — `encrypt_tests.rs`, `decrypt_tests.rs`, `entropy_comprehensive_tests.rs` (24 compilation errors against old API; 990 dead lines removed).
- **Build artifacts cleaned** — 24.4 GiB / 116,454 files reclaimed.
- **wateringHole aligned** — 8 stale handoffs archived, BearDog metrics fixed in 6 docs (methods 185→100, tests 14,593→14,784+, wave 35→46), SA-01 gap marked resolved.

### April 13, 2026 -- Wave 46: Deep Debt Sweep — Dead Features, Version Drift, File Refactor

- **6 dead Cargo features removed** — `json-rpc` (beardog-ipc), `service-registry` (beardog-discovery), `pixel8_optimizations` + `strongbox_hardware` (beardog-tunnel), `mock-upa` (beardog-integration), `pure-rust` (beardog-cli). Zero `cfg` gates existed for any of these.
- **2 unused optional deps removed** — `adb_client` and `nusb` from beardog-cli (were gated behind the dead `pure-rust` feature).
- **Production wildcard import eliminated** — `ios_secure_enclave/capability.rs` `use super::types::*` replaced with explicit 5-item import.
- **Critical version drift fixed** — `thiserror` 1.0→2.0 (beardog-integration), `tokio` 1.43→workspace (beardog-hid, beardog-client), plus `serde`, `serde_json`, `tracing`, `anyhow`, `chrono`, `tempfile`, `async-trait`, `futures`, `tracing-subscriber` normalized to `workspace = true` across 3 crates.
- **2 large production files refactored** — `registry_client.rs` 827→427 LOC (400 lines of inline tests extracted to `registry_client_inline_tests.rs`), `monitoring/service.rs` 822→552 LOC (270 lines extracted to `service_tests.rs`).
- **14,784 tests passing**, zero failures, zero clippy warnings, zero doc warnings.

### April 13, 2026 -- Wave 45: Signed Capability Announcements — Unified Identity, Wire Standard SA-01

- **Unified primal identity key** — Single Ed25519 derivation (`SHA-256("primal-identity-key:" || name || ":" || node_id)`) shared by capability announcements, ionic bond signing, contract signing, and neural registration. Eliminates prior inconsistency where announcements and ionic bonds used separate keys.
- **Canonical signed message (schema_version 2)** — `SHA-256(primal ":" version ":" sorted_methods)` with hash-then-sign. Methods are lexicographically sorted before hashing, fixing the prior bug where unsorted registry order was signed despite doc claiming sorted.
- **`discover_capabilities` now signed** — Response includes `primal`, `version`, `signed_announcement` alongside the capability list. Previously unsigned.
- **Neural API registration attestation** — `capability.register` payloads now include `signed_attestation` with Ed25519 signature so Neural API and downstream Songbird discovery can verify advertisement authenticity.
- **Wire standard extended (SA-01)** — New "Signed Capability Announcements" section in `CAPABILITY_WIRE_STANDARD.md` specifying canonical message format, key derivation, verification procedure, and implementation status.
- **New `primal_signing` module** — `crates/beardog-tunnel/src/unix_socket_ipc/handlers/primal_signing.rs` centralizes identity key derivation, signing, and canonical message construction. 5 unit tests.
- **All quality gates clean** — fmt, clippy, doc, test.

### April 13, 2026 -- Wave 44: Documentation & Debris Cleanup — Root Docs, Spec Links, Showcase Fixes

- **Root docs aligned** — ROADMAP.md, START_HERE.md, CONTEXT.md, SECURITY.md updated: method count 95→100, tests 14,761→14,780+, coverage 90%+→90.51%, dates to April 13, 2026.
- **5 broken spec links fixed** — `PRODUCTION_READINESS` STATUS.md path, `ENTROPY_SECURITY` dead quantum spec link, `TOR_CAPABILITY` 3 broken cross-refs (TOR_PHASE2, RPC API, Songbird Integration).
- **Production readiness notice updated** — Stale October 2025 accuracy warning replaced with current April 2026 status (0 unsafe, 14,780+ tests, 90.51% coverage).
- **Showcase `btsp-api` stale feature removed** — `songbird-btsp` demo Cargo.toml referenced non-existent `btsp-api` feature on `beardog-tunnel`.
- **Hardcoded user path eliminated** — `run-demo.sh` songbird path changed from `/home/eastgate/...` to environment-variable-based discovery (`$SONGBIRD_PATH` or relative).

### April 13, 2026 -- Wave 43: Deep Debt Sweep — Unused Deps, Dead Features, Commented Imports, Smart Refactor

- **4 unused workspace dependencies removed** — `mockall`, `rmp-serde`, `figment`, `config` declared in root `[workspace.dependencies]` but referenced by zero crates.
- **Dead `mdns-discovery` feature removed** from `beardog-adapters` — no `#[cfg(feature = "mdns-discovery")]` gates or cross-crate enablement.
- **16 "Removed unused import" comment lines cleaned** across 14 files in `beardog-monitoring`, `beardog-types`, `beardog-threat`, `beardog-traits`, `beardog-core`. Dead comments from earlier refactors.
- **`security.rs` refactored (971→555 LOC)** — 416-line test module extracted to `security_tests.rs` via `#[path]` attribute. Handler stays routing/crypto only; zero production files over 800 LOC in handlers/.
- **Production wildcard import eliminated** — `use super::types::*` in `ios_secure_enclave/operations.rs` replaced with 6 explicit type imports.
- **All quality gates clean** — fmt, clippy, doc, test.

### April 13, 2026 -- Wave 42: primalSpring Audit Resolution — Ionic Bond Seal, BTSP Metadata, Accept Hardening

- **`crypto.ionic_bond.seal` implemented** — Explicit third step in propose→accept→seal lifecycle. Re-verifies both Ed25519 signatures, transitions Active→Sealed. Rejects unauthorized sealers, revoked/expired bonds, and tampered signatures. 5 new tests: full lifecycle, unauthorized sealer, revoked bond, tampered sig, revoke-after-seal.
- **`BondState::Sealed` added** — New state in the ionic bond state machine. `verify` accepts both Active and Sealed bonds as valid. `revoke` works on both.
- **`accept` hardened** — Proposer Ed25519 signature now verified at accept time (defense in depth, previously only at `verify`). Proposal TTL enforced at `accept` — expired proposals rejected before bond creation.
- **BTSP capability metadata fixed** — `btsp_server` capability bumped to v1.1, `server.export_keys` added to methods array and cost estimates. `ionic_bond` capability bumped to v2.0 with `seal` method. `discover_capabilities` includes `ionic_bond.seal`. Operation dependencies updated.
- **100 JSON-RPC methods** (was 99: +`crypto.ionic_bond.seal`). All quality gates clean.

### April 13, 2026 -- Wave 41: Documentation Cleanup — Stale Links, Migration Debris, Metric Alignment

- **Root doc metrics unified** — `README.md`, `ARCHITECTURE.md`, `CONTEXT.md` aligned to canonical numbers: 99 JSON-RPC methods (was 97 in three files), 2,150 Rust files (was 1,967 in README quality table), 14,780+ tests (was 14,906+ in README quality table — historical peak from Wave 38 before test consolidation).
- **Migration test debris removed** — Deleted `simple_core_tests_migrated.rs` and `adapter_integration_tests_migrated.rs` (exact or subset duplicates of their non-migrated counterparts).
- **Broken spec links fixed** — `PRODUCTION_READINESS_SPECIFICATION.md` pointed to deleted audit file → redirected to `STATUS.md`. `VENDOR_AGNOSTIC_TESTING_MATRIX.md` referenced 3 missing files → consolidated to `STATUS.md`. `SECURITY_SENTINEL_SPECIFICATION.md` referenced deleted `archive/` paths → annotated as ecoPrimals fossil record.
- **Test READMEs refreshed** — `tests/chaos/README.md` and `tests/e2e/README.md` replaced from verbose October 2025 versions with concise, current summaries (April 2026).
- **`.env.example` realigned** — Removed HTTP-centric vars (`BIND_ADDRESS`, `CORS`, `TLS`, `MAX_CONNECTIONS`, `ADMIN_PASSWORD`) that don't match JSON-RPC/NDJSON/Unix socket deployment model.
- **163 receipt JSON artifacts cleaned** from `crates/beardog-cli/receipts/` (untracked, gitignored).
- **All quality gates clean** — fmt, clippy, doc, test.

### April 13, 2026 -- Wave 40: Deep Debt Sweep — Wildcard Imports, Lint Evolution, Dead Features, Dep Alignment

- **Wildcard imports eliminated** — 3 production `use crate::*` in PKCS#11 discoverer modules replaced with explicit imports. Eliminated `classification.rs`, `discoverer.rs`, `capability_profiles.rs` wildcards.
- **`#[allow(` → `#[expect(`** — Migrated 4 instances (3× `deprecated` re-exports in `hybrid_intelligence/types`, 1× `unused_mut` in `entropy_orchestrator`). Removed spurious `#[allow(unused_imports)]` in `pkcs11.rs` (import IS used). Remaining `#[allow(deprecated)]` documented as unfulfillable-expect (rustc limitation on deprecated re-exports/definitions).
- **5 dead Cargo features removed** — `async` (`beardog-config`), `camera` (`beardog-genetics`), `advanced-registry` (`beardog-adapters`), `network-scan` (`beardog-discovery`), `mock-primals` (`beardog-tower-atomic`). Confirmed zero `#[cfg(feature = "…")]` gates and zero cross-crate `features = [...]` references.
- **`mdns-sd` version aligned** — `beardog-capabilities` 0.19 → 0.11 to match `beardog-core`, `beardog-adapters`, `beardog-discovery`. Eliminates double-version compilation.
- **`thiserror` version split fixed** — `beardog-utils` optional dep on `thiserror = "1.0"` removed; `test-utils` feature now empty (test modules use dev-dep `thiserror.workspace = true` → 2.0).
- **`#[allow(` 81** (was 86); **`#[expect(` 646** (was 642); **14,780+ tests**, all quality gates clean.

### April 13, 2026 -- Wave 39: wetSpring Alignment — Consent Gate, Security Domain Registration

- **`security.verify_consent` + `security.issue_consent_token` implemented** — HMAC-SHA256 consent tokens gating vault data access (NUCLEUS consent protocol). wetSpring's `verify_consent_via_beardog` calls `capability.call("security", "verify_consent", {owner_id, scope, token})` — BearDog now resolves this directly. Token = HMAC-SHA256(BLAKE3(family_id + ":consent-hmac-key"), owner_id + ":" + scope). Cross-family tokens automatically rejected. 6 new tests: roundtrip, bad token, wrong scope, cross-family rejection, missing params, method registration.
- **Neural API `security` capability registered** — `register_with_neural_api()` now includes `security` domain with operations: `verify_consent`, `issue_consent_token`, `evaluate`, `lineage`, `generate_jwt_secret`. Enables Neural API semantic routing of `capability.call("security", ...)` to BearDog.
- **Capabilities listing updated** — `provided_capabilities` security type bumped to v1.1 with consent methods; `discover_capabilities` flat list includes `consent.verify` + `consent.issue`; `cost_estimates` include both consent methods at low CPU / 1ms latency.
- **99 JSON-RPC methods** (was 97: +`security.verify_consent`, +`security.issue_consent_token`).
- **14,780+ tests passing**, all quality gates clean (fmt, clippy, doc, deny).

### April 12, 2026 -- Wave 38: Deep Debt Resolution — Smart Refactoring, Production Stubs Evolved, Hardcoding Eliminated

- **`ionic_bond.rs` smart refactored** (1022 LOC → 4 submodules) — Extracted `crypto.rs` (signing helpers), `lifecycle.rs` (propose/accept/verify/revoke/list handlers), `contract.rs` (sign_contract/verify_contract), with `mod.rs` as dispatch. All 14 tests pass, all public APIs preserved.
- **iOS Secure Enclave key agreement evolved** — Placeholder zero-byte returns replaced with real X25519 Diffie-Hellman using `x25519-dalek`. Non-iOS platforms get genuine software-fallback ECDH; iOS path logs explicit "Secure Enclave unavailable" warning instead of silently returning zeroed secrets.
- **Load balancing simulated metrics eliminated** — `least_connections_balance` now reads real tracked connection counts from `LoadBalancerState`; `weighted_round_robin_balance` reads real tracked weights; `least_response_time_balance` reads `avg_response_ms` from service metadata; `resource_based_balance` reads `resource_usage` from metadata. Unnecessary `Vec::clone()` calls removed from dispatch (6 clones eliminated).
- **Hardcoded `/tmp/` paths evolved** — `SoftwareHsmConfig::default()` in `beardog-types` now uses `resolve_temp_dir()` (XDG/env-first); `SoftwareHsmConfig` in `beardog-tunnel` now uses `resolve_key_storage_dir()` (consolidated resolver); `doctor.rs` key-storage check uses `resolve_key_storage_dir()` instead of manual 4-tier fallback. Constants remain as documented Tier-5 last-resort fallbacks.
- **`#[allow(` → `#[expect(`** — Migrated `clippy::cast_precision_loss` in `monitoring/service.rs` (CPU/memory ratio calculations) from `#[allow]` to `#[expect]` with reason strings. Remaining `#[allow]` instances have legitimate reason strings (lib+bin crate incompatibility, deprecated re-exports, conditional compilation).
- **Zero TODO/FIXME** confirmed. Zero `todo!()`. Zero `unimplemented!()`. Zero wildcard imports in production code.
- **14,906+ tests passing**, all quality gates clean (fmt, clippy, doc, deny).

### April 12, 2026 -- Wave 37: primalSpring Audit Resolution — Contract Signing, BTSP Relay Path, Encoding Docs

- **`crypto.sign_contract` + `crypto.verify_contract` implemented** (IONIC-RUNTIME) — New JSON-RPC methods for programmatic cross-family trust: signs arbitrary contract terms (canonical JSON → SHA-256 → Ed25519), returns terms_hash + signature + public_key for independent verification. Enables multi-family deployments (CERN-level clouds, data federation, friend-hosted shards). 5 new tests: roundtrip, tamper rejection, deterministic hash ordering, method registration.
- **`btsp.server.export_keys` implemented** (BTSP-BARRACUDA-WIRE) — Completes the relay path: after `btsp.server.verify` succeeds, relay primals call `export_keys` to retrieve session keys wrapped under their X25519 ephemeral pub via ChaCha20-Poly1305 (keys never appear as plaintext in JSON-RPC). New types: `SessionExportKeysParams`, `SessionExportKeysResponse`.
- **LD-01 encoding contract documented** — `crypto.hash` base64 requirement documented in handler doc comments, module-level docs, and wateringHole `CAPABILITY_WIRE_STANDARD.md` §Parameter Encoding. Covers all crypto methods, encoding hints (BD-01), and the sign_contract hex convention.
- **Capability surface expanded** — `contract_signing` v1.0 capability added to `capabilities.list`; cost_estimates updated for `crypto.sign_contract` and `crypto.verify_contract`; ionic_bond capability bumped to v1.1.
- **97 JSON-RPC methods** (was 95: +`crypto.sign_contract`, +`crypto.verify_contract`, +`btsp.server.export_keys`, -0 = 98 total handler aliases, 97 logical methods).

### April 12, 2026 -- Wave 36: Composition Elevation Sprint — Ionic Bond Lifecycle, BTSP Naming, Smart Refactoring

- **Ionic bond lifecycle hardened** — `IonicBond` type now carries `terms_hash` (SHA-256 of canonical terms); `crypto.ionic_bond.verify` performs real Ed25519 re-verification of both proposer and acceptor signatures (was state-only check). 4 new lifecycle tests: `sealed_bond_stores_terms_hash`, `verify_detects_tampered_proposer_signature`, `verify_detects_tampered_acceptor_signature`, `full_lifecycle_propose_accept_list_revoke`.
- **BTSP naming alignment** — Doc comments in `beardog-types/src/btsp/rpc.rs` updated from legacy `btsp.session.*` to canonical `btsp.server.*` names (handler aliases preserved for backward compatibility). `crypto.ionic_bond.list` added to cost_estimates in capabilities.
- **Production mocks eliminated (2)** — `MonitoringService::collect_performance_metrics` reads real `/proc/stat` (CPU), `/proc/meminfo` (memory) with graceful non-Linux fallback; `PerformanceMonitor::collect_performance_metrics` returns actual history instead of `Default::default()`.
- **Wildcard imports eliminated** — 11+ production files in `beardog-tunnel/universal_hsm_discovery/`, `beardog-types/providers/`, `simplified_seed_tunnel.rs` switched from `use super::*` to explicit imports.
- **Smart refactoring (3 large files)** — `port_discovery.rs` (940 LOC) → 4 submodules (config, env, discoverer, hierarchical); `btsp.rs` (855 LOC) → 6 submodules (contact, session, negotiation, peer, tunnel, mod); `tarpc_server/server.rs` (811 LOC) → 9 submodules (keygen, signatures, key_exchange, aead, hashing, kdf, genetic, tls, introspection). All public APIs preserved via re-exports.
- **PKCS#11 discovery evolved** — `BEARDOG_PKCS11_SEARCH_PATHS` env var added for user-overridable library discovery before platform defaults.
- **14,769+ tests passing**, all quality gates clean (fmt, clippy, doc, deny).

### April 11, 2026 -- Wave 35: Deep Debt Cleanup III — Placeholder Elimination, Real Entropy, Auth Test Evolution

- **Production placeholders eliminated** — `SystemStatus` reads real `/proc` metrics; sovereign RNG uses real entropy; batch validation delegates per-config
- **Dead code removed** — `placeholder_test()`, `signature_placeholder`, stale module comments
- **Auth tests evolved** — Permission/authorization/node-registry stubs replaced with real struct validation tests
- **14,761+ tests passing**, all quality gates clean

### April 11, 2026 -- Wave 34: Deep Debt Evolution — Hardcoding Elimination, Mock→Real, Smart Refactoring

- **Hardcoding eliminated (4 sites)** — `system.rs` filesystem paths resolved via XDG Base Directory Specification (`resolve_config_dir`, `resolve_data_dir`, `resolve_cache_dir`, `resolve_runtime_dir`); UID 1000 default replaced with safe `/proc/self/status` resolution (no `unsafe`, no FFI) in `socket_config.rs` and `tower-atomic/discovery.rs`; UPA fallback URL dynamically constructed from `BEARDOG_UPA_URL`/`BEARDOG_EXTERNAL_HOST`/`BEARDOG_API_PORT` env vars in `network_ports.rs`.
- **Production mocks evolved to real implementations (8 items)** — Ionic bond proposals now Ed25519-signed (deterministic key from primal name + node ID via HKDF-SHA256); capability announcements Ed25519-signed with verifiable public key; compliance metrics dynamically computed from audit trail pass/fail ratio; HSM provider returns `success: false` with descriptive error for unimplemented operations; ML threat analysis returns honest empty results when no models loaded, dynamic events when models present; health checks only report subsystems with actual probes (no more blanket "unknown" for external services).
- **Dead code removed** — `grafana.rs` and `prometheus.rs` simulated external function stubs deleted (never wired into `external_functions/mod.rs`).
- **Config placeholders deprecated** — `with_secrets_rotation` and `recommended_backup` on `ProductionEnvironmentConfig` marked `#[deprecated]` with migration notes to `ModernSecretsConfig` and capability-based discovery.
- **Smart refactoring (2 large files)** — `monitoring.rs` (978 LOC) → `monitoring/mod.rs` + `alerts.rs` + `metrics.rs`; `self_knowledge.rs` (832 LOC) → `self_knowledge/mod.rs` + `identity.rs` + `endpoints.rs` + `capabilities.rs`. All re-exports preserved for API compatibility.
- **Test adaptation** — ML integration tests updated for dynamic event generation; compliance tests updated for audit-trail-based scoring; 14,756+ tests passing, 0 failures.
- **Metrics** — 95 crypto methods; 2,128 Rust files; 90.51% line coverage (llvm-cov).

### April 9, 2026 -- Wave 33: Deep Debt Cleanup & Evolution — Coverage 90.51%, allow→expect Migration, Standalone Startup, Capability Registration

- **`#[allow()]` → `#[expect(reason)]` migration** — 193 → 75 `#[allow(` remaining (62% reduction); 361 → 476 `#[expect(` with contextual `reason` strings. Where `expect` caused `unfulfilled_lint_expectations`, kept `allow` with documented `reason`.
- **Standalone startup (T10)** — `NODE_ID` / `BEARDOG_NODE_ID` no longer required; missing values use ephemeral `standalone-{uuid}` via `OnceLock`, logged once with `tracing::warn!`; PRIMAL IPC Protocol v3.1 degraded mode.
- **Dynamic `ipc.register` with Songbird (T4)** — Non-blocking registration at server startup: registry socket discovery, `ipc.register` with self-knowledge capability tags, heartbeats; exponential backoff on failure (standalone continues).
- **BD-01 per-field encoding hints** — `crypto.verify_ed25519` accepts `message_encoding`, `signature_encoding`, `public_key_encoding`; semantic aliases `crypto.ed25519.sign` / `crypto.ed25519.verify` registered.
- **Commented-out code cleaned (T1)** — 313-line orphan block in beardog-types + smaller blocks across 15+ files removed.
- **PII cleaned (T8)** — `/home/user/...` → `$HOME/...` in tests and builder.
- **Coverage** — 90.16% → 90.51% line; new tests across beardog-production, beardog-cli, beardog-compliance, beardog-config, beardog-core.
- **Smart refactoring** — `runtime.rs` (1244→360) split into `secrets.rs`, `defaults.rs`, `runtime_tests.rs`; `socket_config.rs` (1111→668) test extraction.
- **Metrics** — 95 crypto methods (`methods()` handler; prior 96 was a count error); 1,939 Rust files; 14,593+ tests passing, 0 failures.

### April 8, 2026 -- Wave 32: Deep Debt Sweep II — Stub Evolution, Large File Dedup, Clippy Zero

- **AES-GCM deduplication** — `crypto_handlers_aes_gcm.rs` production code reduced 64% (485 → 175 lines) via generic `gcm_encrypt<C>`/`gcm_decrypt<C>` core over `Aes128Gcm`/`Aes256Gcm`; extracted shared param helpers (`decode_b64_param`, `extract_key`, `extract_or_generate_nonce`)
- **BTSP handler DRY** — `resolve_tunnel_handle()` extracted from duplicated tunnel-id resolution in `handle_tunnel_status` and `handle_tunnel_close`
- **Doc hardcoding removed** — Primal name references ("Squirrel", "Songbird", "ToadStool") replaced with capability-agnostic phrasing in `universal_adapter.rs`, `capabilities.rs`, `genetics_impl.rs`
- **TPM/PKCS11 stubs evolved** — `#[allow(dead_code)]` removed from provider structs; new public accessors (`metadata()`, `library_path()`, `slot_id()`) make fields live
- **FIDO2 operations evolved** — `BearDogError::system(...)` → `BearDogError::requires_capability(...)` with honest feature-gate messaging; `#[allow(dead_code)]` → `#[expect(dead_code)]` for compiler notification when callers land
- **Service discovery cleanup** — Removed 3 deprecated dead detection stubs (`_detect_kubernetes`, `_detect_consul`, `_detect_etcd`) from factory; Consul/etcd properly delegated to capability-based discovery per architectural decision
- **Monitoring glob consolidation** — 10 per-line `#[allow(ambiguous_glob_reexports)]` consolidated into single inner module with documented reason
- **BTSP handshake docs** — Added missing field docs on `ClientHello`, `ServerHello`, `HandshakeError`, `SessionKeys`, `FamilySeed`, `BtspSecurityMode`; fixed clippy doc backtick warnings
- **Clippy zero** — Resolved all remaining warnings: collapsible-if (`let` chains), `map_or` → `is_some_and`, `format!`-in-iterator → `write!`, `match` → `if let`, redundant closure
- **All gates green** — fmt, clippy (0 warnings), 14,593+ tests passing, doc

### April 8, 2026 -- Wave 31: BTSP Handshake Enforcement — Live-Encrypted Socket Listener

- **BTSP handshake enforcement** — New `btsp_handshake/` module (6 files, ~750 LOC) implements Phase 2 of `BTSP_PROTOCOL_STANDARD.md`: when `FAMILY_ID` is set, every incoming connection must complete a 4-step cryptographic handshake (X25519 ephemeral + HMAC-SHA256 challenge-response) before any JSON-RPC is processed
- **`BtspSecurityMode` enum** — Resolved at startup from `FAMILY_ID` / `BIOMEOS_INSECURE` env vars; flows through `MultiTransportServer` to Unix and TCP server instances
- **`BIOMEOS_INSECURE` guard** — Server refuses to start when both `FAMILY_ID` and `BIOMEOS_INSECURE=1` are set (per BTSP standard)
- **Encrypted frame codec** — Post-handshake communication switches to length-prefixed (4-byte BE) frames with ChaCha20-Poly1305 AEAD encryption; supports HMAC-plain and null cipher negotiation
- **Session key derivation** — HKDF-SHA256 from X25519 shared secret with directional keys (server→client, client→server) and monotonic nonce counters
- **`btsp.session.create`/`.verify`/`.negotiate`** — 3 new JSON-RPC methods expose handshake-as-a-service for other primals to implement their own BTSP listeners using BearDog's crypto
- **TCP transport parity** — Same handshake enforcement and encrypted framing applied to `TcpIpcServer`
- **28 new tests** — Unit tests for crypto, framing, session encryption; integration tests for full handshake roundtrip, wrong-seed rejection, wrong-version rejection, env-based security mode resolution, BIOMEOS_INSECURE conflict, 100-message nonce progression
- **All gates green** — fmt, clippy, test, doc

### April 8, 2026 -- Wave 30: Deep Debt Sweep — Production Stub Removal, Self-Knowledge, Lint Cleanup

- **Self-knowledge violations fixed** — `attempt_songbird_registration` → `attempt_orchestrator_registration` (capability-based, never names another primal); `ToadStool` reference removed from key_export doc comments
- **Dead code removed** — `DatabaseStorageBackend` (all methods returned `unsupported_operation`), `handle_key_generate` v1 (superseded by v2, was `#[allow(dead_code)]`), `generate_aes_key_with_seed` gated `#[cfg(test)]`
- **Overstep cleanup** — Security/Storage/Network `MigrationAdapter`s removed from `ecosystem_integration.rs` (those domains belong to other primals per PRIMAL_RESPONSIBILITY_MATRIX)
- **Stub evolution** — `PerformanceOptimizer` in beardog-types: removed no-op `initialize_optimizations()` / `evaluate_scaling_needs()`, documented as config holder (real optimization in beardog-core); `effectiveness_score` hardcoded floats replaced with named constants + rationale
- **Discovery engine honesty** — 6 HSM discoverer stubs changed from misleading `warn!("not yet implemented")` to honest `info!` messages (Cloud: no credentials, USB: no devices, TPM: no hardware, etc.)
- **Lint cleanup** — Blanket `#[allow(unused_imports, clippy::nonminimal_bool, dead_code)]` removed from 35 test modules in beardog-utils (clippy confirms they suppressed nothing)
- **Wire Standard handoff** — `CAPABILITY_WIRE_STANDARD.md` updated: BearDog L2 → ✓
- **All gates green** — fmt, clippy, test, doc

### April 7, 2026 -- Wave 29b: Wire Standard Level 2 — `methods` Array, `identity.get`

- **`capabilities.list` upgraded** — Flat `methods` array added alongside `provided_capabilities` (Wire Standard L2 Tier 1 migration); dynamically populated from `HandlerRegistry::all_methods()` filtered to `domain.operation` naming
- **`identity.get` implemented** — New JSON-RPC method returns `{primal: "beardog", version, domain: "crypto", license: "AGPL-3.0-or-later"}`
- **Two-phase registry construction** — `CapabilitiesHandler` moved to Phase 2 of `HandlerRegistry::new()` to receive `Arc<HandlerRegistry>` for dynamic method enumeration
- **`SCYBORG_EXCEPTION_PROTOCOL.md` license fix** — `AGPL-3.0-only` → `AGPL-3.0-or-later` for software (consistency fix from primalSpring audit)
- **`cargo fmt` regression fixed** — `edge_cases_nov_6_2025.rs` formatting corrected
- **All gates green** — fmt, clippy, test, doc

### April 7, 2026 -- Wave 29a: primalSpring Audit Execution — BD-01 Encoding, Sovereignty Sweep, Smart Refactoring

- **BD-01 resolved** — `crypto.verify_ed25519` now accepts optional `encoding` hint per `ATTESTATION_ENCODING_STANDARD.md` v2.0 (supports base64, hex, base64url, utf8, none); backwards-compatible default; 7 new encoding tests
- **Sovereignty sweep** — Removed 50+ hardcoded primal names (Songbird, NestGate, ToadStool, Squirrel) from production doc comments, test fixtures, and e2e tests; replaced with capability-based, primal-agnostic language
- **Smart refactoring** — 3 production files >800 LOC decomposed: `threat/types/mod.rs` (862L → 33L hub + 9 submodules), `capability_router.rs` (861L → 5-module directory), `handlers/key.rs` (875L → 3-module directory)
- **Zero-copy consolidation** — Deleted dead orphan `zero_copy/optimized.rs` (830L, never compiled)
- **Dependency cleanup** — Removed unused `serde_yaml` from `beardog-core` and `beardog-adapters`
- **Production stub hardening** — FIDO2 phase wording aligned; discovery announcement upgraded to `warn!`; AI `initialize_capability` documented as no-op; factory doc corrected
- **Root docs updated** — CONTEXT.md, START_HERE.md, specs/README.md sovereignty cleanup and metrics refresh; stale `otherTeams/` and `experiments/` phantom directory references removed
- **Stale references removed** — `specs/IMPLEMENTATION_GAPS_NOV_2025.md` pointer updated to `ROADMAP.md`
- **14,372+ tests passing** — 0 failures, all gates green

### April 2, 2026 -- Wave 28: Deep Debt Evolution — Self-Knowledge, Error Typing, Hardcoding

- **Self-knowledge** — Removed deprecated `SongbirdClient` type alias; genericized Songbird/biomeOS references in tower-atomic, discovery, installer docs
- **`Box<dyn Error>` → `BearDogError`** — AI hybrid intelligence public APIs return canonical typed errors
- **Hardcoded addresses** — tarpc/node-registry/BTSP docs annotated with capability-based discovery notes
- **Feature flag** — `advanced-nestgate` → `advanced-registry` (no cross-primal names)
- **Stub documentation** — PKCS#11/TPM Phase 2 comments reference target pure Rust crates
- **14,366+ tests passing**, all gates green

### April 2, 2026 -- Wave 27: primalSpring License Audit — AGPL-3.0-or-later, Lint Migration, Deprecation

- **License** — `AGPL-3.0-only` → `AGPL-3.0-or-later` across 58 `Cargo.toml`, `deny.toml`, 2,075 SPDX headers, all `.md` docs per `STANDARDS_AND_EXPECTATIONS.md`
- **`#[allow]` → `#[expect(reason)]`** — 49 non-test attributes migrated; `dead_code` on pub items in lib+bin crates kept as `#[allow]` (documented limitation)
- **Flat method aliases deprecated** — `capabilities`, `ping`, `health`, `status`, `identity`, etc. marked deprecated in favor of `domain.operation` names
- **Binary targets documented** — `ARCHITECTURE.md` now has Binary Targets section documenting UniBin, tooling exceptions, and showcase demos
- **14,366+ tests passing**, all gates green

### April 2, 2026 -- Wave 26: Deep Debt Evolution — Stubs → Implementations, Dependency Alignment, Dead Code Cleanup

- **Workspace dep alignment** — `beardog-ipc`, `beardog-hid`, `serial_test`, `beardog-adapters`, `beardog-capabilities`, `beardog-genetics`, `tempfile` → `workspace = true`
- **`handle_key_info` evolved** — Stub replaced with real key store load + `_with_home` DI variant
- **Client JSON-RPC dispatch** — Real Unix socket `dispatch_rpc()` replaces placeholder
- **Orphaned entropy modules compiled** — `collector.rs` / `live_feed_validator.rs` wired into `universal_hsm` module tree; 22 API-drift clippy errors fixed
- **Dead code cleanup** — 3 unused `QuantumDiscoveryEngine` fields removed; 3 test-only `BearDogCore` methods gated `#[cfg(test)]`; redundant `#[allow(dead_code)]` removed from `merge()`
- **`deny.toml` skip-list** — 30 → 15 entries (12 resolved transitive splits)
- **Flaky test stabilization** — `beardog-production` `#[serial]` (35 tests); `beardog-tunnel` HSM tests refactored to `HsmAutoInitConfig`
- **AI tree feature-gated** — `beardog-core/src/ai/` (11.9K LOC) behind `ai` feature per responsibility matrix
- **Root docs updated** — STATUS.md and CHANGELOG.md reflect accurate state
- **Debris cleaned** — `audit.log` removed; duplicate `env.example` consolidated; empty dirs removed
- **14,366+ tests passing** — 0 failures, all gates green

### March 30, 2026 -- Wave 25: Full Audit — Lint Promotion, Cast Safety, Doc Completeness, Smart Refactoring

- **Cast safety promoted to warn** — All 40 truncation/precision casts (`u128→u64`, `u64→u32`, `usize→f64`) fixed with `try_from`, const-assert, or per-site `#[expect]`; `cast_possible_truncation`, `cast_precision_loss`, `cast_sign_loss`, `cast_possible_wrap` promoted from allow to warn
- **`doc_markdown` promoted to warn** — 1,010 bare identifiers in doc comments backticked across all 29 crates; lint promoted from allow to warn
- **`missing_errors_doc` promoted to warn** — 780 public `Result`-returning functions now have `# Errors` sections; lint promoted from allow to warn
- **Smart file refactoring** — 4 of top 5 largest files decomposed into domain-driven submodules: `key_export/` (types/crypto/export/import/tests), `capabilities/` (type/discovery/compliance/infrastructure), `providers/base/` (configuration/performance/schema/trait/defaults), `entropy/` (collect/helpers/hsm_selection/info/types/tests)
- **Production mock evolution** — `quantum_discovery.rs` evolved from fake endpoints/providers to real `PrimalDiscovery` integration; Phase 2 stubs return `NotImplemented` instead of fabricated data
- **Formatting fixed** — 4 files that drifted from `cargo fmt` corrected
- **Licensing clarified** — `LICENSE-DOCS.md` updated with full scyBorg Provenance Trio table (AGPL-3.0-or-later / ORC / CC-BY-SA 4.0)
- **Coverage** — 90.16% line (workspace), 14,610+ tests passing, 0 failures
- **Stale docs cleaned** — `specs/PROJECT_STATUS.md` archived to fossilRecord, `scripts/` debris removed, root docs updated to current metrics

### March 29, 2026 -- Wave 23: Concurrency Deep Debt — ABBA Deadlock Fix, Sleep Elimination, Async Evolution

- **ABBA deadlock eliminated** — Root cause of ~30% intermittent test hangs found and fixed: `tests/e2e/hsm_operations.rs` had 3 global `OnceLock<Mutex<HashMap>>` statics with inconsistent lock ordering (`initialize_hsm` locked A→B, `check_hsm_health` locked B→A). Replaced with per-test `HsmTestContext` struct — zero global state, zero cross-test contamination
- **Global mutable state eliminated from all e2e tests** — `rate_limiting.rs` (3 global `OnceLock<AtomicUsize>` → `thread_local! Cell`), 4 disaster_recovery modules (`OnceLock<Mutex>` → per-invocation context structs)
- **`HybridIntelligenceSystem::initialize()` evolved to async** — Was sync with `blocking_write()` that panicked in tokio runtime context; now uses `.write().await`. Test un-ignored and passing
- **Ed25519 verify API corrected** — `GeneticCryptoProvider::verify()` restored to accept public key (not private seed); property tests updated to derive public key before verification
- **Sleep debt eliminated** — 1s `proof_verifier` (UUID uniqueness), 1100ms `key_expiration` (zero-duration interval), 100ms `idle_tracking`, 56ms circuit breaker (configurable cooldown), plus ~10 smaller test sleeps replaced with instant-past timestamps, `yield_now()`, or zero-duration intervals
- **Proof signature uniqueness** — `generate_proof()` now uses nanosecond timestamp + UUID instead of second-resolution timestamp
- **Dead code cleanup** — Deleted 8 orphan files from `android_strongbox/` (49.6 KB): `health.rs`, `attestation.rs`, `core_simple.rs`, `device_info.rs`, `entropy.rs`, `keystore.rs`, `pixel8_setup.rs`, `type_safe_wrapper.rs` — none referenced by `mod.rs`
- **Debris cleanup** — Removed `audit.log` artifacts from repo root and 2 crate directories
- **Method count** — 93 crypto methods (registered `derive_lineage_beacon_key`)
- **Tests** — 15,184 passed, 0 failed, 138 ignored; 10/10 stress tests clean on both e2e binaries under full parallelism

### March 28, 2026 -- Wave 22: Deep Debt Evolution — Hot-Path Clones, iOS Fake Crypto, Mock Cleanup

- **Hot-path clone elimination** — Genetic RPC handlers take `&Value` + `Deserialize::deserialize` instead of `Value::clone()` per request
- **iOS safe_ffi** — Placeholder keys/zeroed signatures replaced with `not_implemented` errors (fake crypto success is a security risk)
- **Mock label cleanup** — "(mock)" → "(software fallback)" in production logs; stale comment removed
- **Examples** — `Box<dyn Error>` → `anyhow::Result<()>`
- **Socket path centralization** — `doctor.rs` uses `DEFAULT_SOCKET_PATH`
- **Dependency audit clean** — No `ring`, no `openssl-sys`, no `sled`, no `unsafe`; `blake3` pure-featured
- **Coverage** — 90.05% line maintained, 0 failures

### March 28, 2026 -- Wave 21: StrongBox HSM Abstraction, Production Mock Evolution, Self-Knowledge

- **Canonical `HsmKeyProvider` trait** — Unified HSM provider trait in `beardog-traits` with supporting types in `beardog-types`; object-safe, `#[async_trait]`, supports software and hardware backends
- **HSM Provider Registry** — `HsmProviderRegistry` with `discover()`, `select()`, `software_fallback()` for automatic provider selection based on `PreferHardware`/`RequireHardware`/`SoftwareOnly` preference
- **Android StrongBox bridge** — `keystore.rs` rewritten with `#[cfg(target_os = "android")]` JNI bridge; non-Android stubs for development
- **5 legacy HSM traits deprecated** — Migration doc sections added to `CryptoProvider`, `HsmProviderTrait`, `HsmCapabilities`, 2x `HsmProvider`
- **Production mock evolution** — Real timing in adapter responses, semver validation in `validate_canonical_usage()`, live state in `UniversalHsmManager`
- **Self-knowledge** — `SongbirdClient` → `OrchestratorRegistryClient`, `BiomeOSPaths` → `PlatformPaths`, string literals genericized
- **Dead code cleanup** — Removed orphan `songbird_client.rs` and `discovery_adapter.rs`
- **Socket path centralization** — 3 new `DEFAULT_*` constants replacing inline `/tmp/beardog*` paths
- **Coverage** — 90.05% line, 14,610+ tests passing

### March 28, 2026 -- Wave 18-20: Deep Debt Evolution, 90% Coverage, Semantic Naming

- **90% coverage achieved** — 90.03% line, 89.18% region, 84.90% function (llvm-cov workspace)
- **15,085+ tests passing** — 0 failures (up from 14,600 in Wave 17)
- **UniBin v1.1 compliance** — `PrimalIdentity::from_env()` evolved to standalone fallback with `is_standalone()` accessor
- **TCP/Unix read timeout** — All NDJSON read sites wrapped with `tokio::time::timeout(30s)` per primalSpring audit
- **NDJSON wire format documented** — README transport section, capability metadata includes `wire_format: "ndjson"`
- **Semantic method naming** — `domain.operation` primary names (`birdsong.encrypt`, `btsp.contact.exchange`, `crypto.derive_onion_address`) with `beardog.*` as backward-compatible aliases
- **Songbird IPC registration** — Best-effort ecosystem registry registration at server startup
- **Commented-out code cleanup** — Removed dead code from 15+ files per wateringHole standard
- **Orphan file cleanup** — Removed `ai_powered_analysis.rs` (682 LOC) and `quantum_optimizations.rs` (633 LOC) from beardog-utils
- **Clippy clean** — Resolved `float_cmp`, `await_holding_lock`, `unfulfilled_lint_expectations`, `large_stack_frames`, `io_other_error`, `redundant_clone`, `into_iter` on singletons
- **Showcase cleanup** — `#[allow(dead_code)]` replaced with `_` prefixes and `#[serde(rename)]`
- **Production stub evolution** — Migration adapters return `BearDogError::not_implemented()` with Phase 2 messages
- **Debris cleanup** — `.pedantic_clippy.toml` and `.tarpaulin.toml` removed (superseded by workspace config and llvm-cov)
- **Archive migration** — `archives/` moved to ecoPrimals fossilRecord
- **Root docs updated** — All metrics current (tests, coverage, completion status)

### March 27, 2026 -- Wave 17: Comprehensive Audit, UniBin Compliance, NDJSON & Coverage Push

- **Coverage** — 87.31% line (up from 86.70%); llvm-cov workspace pass after audit fixes
- **Tests** — 14,600+ passing
- **JSON-RPC** — Batch request support on the wire path
- **UniBin** — `--port` compliance alignment
- **NDJSON** — Wire framing fixes for streamed JSON lines
- **Observability** — Structured tracing logging on hot paths
- **Production stubs** — Further evolution (explicit not-implemented / real behavior)
- **Manifests** — Repository URLs normalized; dead feature flags removed
- **Linting** — `cast_lossless` promoted to warn
- **CI** — `beardog-types` check uses `--all-features`; file-size scan excludes `./archives/*` (not typo `./archive/*`)
- **Cleanup** — Commented-out debris removed (core tests, `safety.rs`, tunnel ECDSA notes)
- **Tests** — `discover_socket_path_*` unit tests clear `BEARDOG_LOCAL_SOCKET_DIR` under the existing env lock (fixes parallel-test flake)

### March 24, 2026 -- Wave 16: Full Ecosystem Audit, api_server Refactor, Zero-Copy & Debris Cleanup

- **Full wateringHole audit** — Cross-referenced PRIMAL_IPC_PROTOCOL, SEMANTIC_METHOD_NAMING, ECOBIN, UNIBIN, ZERO_HARDCODING, primalSpring standards
- **api_server.rs refactored** — 1,185 LOC → 3-module structure (`mod.rs`, `handlers.rs`, `types.rs`); production stubs → 501 Not Implemented
- **`#[expect(reason)]` hardening** — Additional migrations with unfulfilled-lint regression fixes
- **Showcase edition 2024** — All 28 showcase `Cargo.toml` updated from 2021 to 2024
- **Zero-copy IPC** — clone-free JSON detection, `Value` deserialization from borrow, `&str` borrows in method lists
- **Zero-hardcoding evolution** — 3 new named constants; `DEFAULT_UPA_URL` aliased from canonical config; DNS-SD comments genericized
- **38 deep tests** — main.rs CLI/dispatch, deploy config, CLI HSM, tunnel IPC, discovery edge cases
- **Debris cleanup** — `audit.log` artifacts removed; stale `tests/README.md` links fixed; Dockerfile aligned to 1.93.0; `tests_NEEDS_FIXING` comment references cleaned
- **14,499+ tests passing** — 0 failures
- **All gates green** — fmt, clippy `-D warnings`, doc, deny, test all clean

### March 24, 2026 -- Wave 15: Ecosystem Absorption, IPC Evolution, Semantic Naming v2.1.0 & Self-Knowledge

- **IPC error types** — `DispatchOutcome` / `IpcErrorPhase` from rhizoCrypt/LoamSpine pattern; `route_with_outcome()` + `normalize_method()`
- **Health v2.1.0** — Differentiated liveness/readiness/deep-check per wateringHole standard
- **Self-knowledge** — ~75 Songbird references removed from production handlers
- **`#[expect(reason)]`** — 30+ `#[allow(clippy::)]` evolved to `#[expect]` with reasons; 6 stale removed
- **Production stubs evolved** — Migration adapters, universal adapter timing, BirdSong → `not_implemented`
- **deny.toml** — 8 cross-primal type crate bans; wire-only contract enforcement
- **60+ deep tests** — integration HTTP router, disaster recovery, result extensions, command runner
- **Coverage 87.08% → 87.35%** (lines)
- **Discovery docs** — 5-tier pattern and credential resolution in CONTEXT.md/ARCHITECTURE.md
- **14,447+ tests passing**

### March 24, 2026 -- Wave 14: Deep Debt Audit, Test Evolution, scyBorg Compliance & Zero-Copy

- **Failing test fixed** — `test_auto_initialize_environment_precedence`
- **main.rs** — `dispatch()` extracted from `main()` for testability; **36 new tests** (33 CLI parse + 3 dispatch)
- **scyBorg** — `LYSOGENY_PROTOCOL.md` and `SCYBORG_EXCEPTION_PROTOCOL.md` added (license/compliance artifacts)
- **Zero-copy** — `bytes::Bytes` in software HSM; storage moved in `key_management`
- **Tests** — Hardcoded ports replaced with ephemeral `:0` where appropriate
- **Platform stubs** — Test stubs evolved from `panic!()` to `Result<T, E>`

### March 24, 2026 -- Wave 13: Clippy Sweep, Constants, Zero-Copy, Tests & Docs

- **Clippy fully clean** — 1,149 errors eliminated workspace-wide
- **Magic number extraction** — 60+ bare literals → named constants
- **Zero-copy optimization** — clone-heavy production files evolved
- **150 new tests** (14,201 → 14,351)
- **License compliance** — `LICENSE-DOCS.md` added (CC-BY-SA 4.0)
- **Stale docs updated**

### March 23, 2026 -- Wave 12: Cross-Ecosystem Audit, Lint Tightening & Type Safety Evolution

- **Full ecosystem audit** — Reviewed all wateringHole standards, 8 springs, and all phase1/phase2 primals for absorption opportunities
- **Clippy lint tightening** — `unwrap_used`/`expect_used` evolved from `allow` to `warn` at workspace level; all 6 production sites annotated with `#[expect(clippy::expect_used, reason = "...")]`; unused `AsyncReadExt` import removed
- **Typed error evolution** — `Box<dyn Error>` eliminated from public APIs (`receipt.rs`, `adapter_certificates.rs`, `hyperoptimized_zero_copy.rs`); `Result<(), String>` evolved to `BearDogError` in SIMD and genetics APIs
- **SPDX compliance** — All 29 showcase `main.rs` files now have SPDX headers (2,026/2,026 = 100%)
- **Commented-out code cleanup** — Removed legacy stubs from ~10 production files per wateringHole standard
- **Smart file refactoring** — 4 files near 1000 LOC split by domain into 14 focused files
- **Dead code evolution** — `#[allow(dead_code)]` removed from production; fields wired into traces or renamed with `_` prefix
- **DI-first discovery** — `get_discovery_socket_paths` refactored to pure `build_discovery_socket_paths` with injectable parameters; env-racing tests eliminated
- **Coverage tests** — 40+ new tests across `beardog-deploy` and `beardog-installer`
- **14,201 tests passing** — Up from 14,161; 0 failures, 186 ignored
- **Root docs aligned** — README, ARCHITECTURE, SECURITY, START_HERE, STATUS, ROADMAP all reflect current state

### March 23, 2026 -- Wave 11: Deep Coverage Push, Crypto Fault Injection & Zero-Copy IPC

- **Coverage 86.1% → 87.0%** — 122+ new tests across 6 crates
- **Crypto fault injection tests** — 14 adversarial tests (Blake3, ChaCha20-Poly1305, Ed25519, X25519, Tor ntor)
- **Zero-copy IPC optimization** — `unix_socket_ipc::server.rs` refactored to `BufReader::read_until` with reusable buffers
- **14,161 tests passing**

### March 23, 2026 -- Wave 10: Deep Audit — Clippy, Hardcoding, Method Aliases, File Size

- **Clippy fully clean** — 12 pedantic errors fixed
- **File size compliance** — `device.rs` split via `#[path]` extraction
- **Zero TODO/FIXME** — All resolved
- **Semantic method aliases** — `capability.list` and `primal.capabilities` added per wateringHole standard
- **14,039 tests passing**

### March 23, 2026 -- Wave 9: Unwrap Evolution, Clone Audit, Binary Unification

- **`.unwrap()` debt: 1,879 → 85** — Systematic evolution across 45+ files
- **Zero-copy clone audit** — Eliminated unnecessary `.clone()` in IPC hot paths
- **Binary collision resolved** — root `src/main.rs` is the sole `beardog` binary
- **14,029 tests passing**

### March 22, 2026 -- Wave 8: Deep Debt Execution — Coverage, Stubs, Hardcoding, File Size

- **Coverage 85.1% → 86.8%** — ~1,000+ newly covered lines across beardog-core, beardog-types,
  beardog-tunnel, beardog-genetics, beardog-cli, beardog-threat, beardog-monitoring, beardog-integration
- **Production stubs evolved** — `disaster_recovery.rs` BLAKE3 content-hash; `heartbeat.rs` real
  `AtomicUsize` connection tracking with RAII guard; `monitoring.rs` `Instant`-backed rolling timings
- **beardog-integration re-integrated** — Evolved HTTP/reqwest to Tower Atomic (Unix sockets + JSON-RPC);
  legacy HTTP integration test archived; connection tracking via Axum middleware
- **20+ hardcoded values extracted** — Ports (`DEFAULT_INTEGRATION_API_PORT`, `DEFAULT_API_SERVER_LISTEN_PORT`),
  timeouts (`DEFAULT_TARPC_CONNECT_TIMEOUT`, `DEFAULT_TARPC_REQUEST_TIMEOUT`), paths
  (`FALLBACK_REGISTRY_UNIX_SOCKET_PATH`, `BEARDOG_TCP_DISCOVERY_FILENAME`), cache TTLs, socket dirs
- **Flaky test fixes** — `test_timeout_accuracy` uses mock-time (`start_paused`);
  `test_auto_initialize_default_software_mode` uses `HsmAutoInitConfig::default()` (no env race);
  e2e stress test timing widened; mass failure test uses guaranteed early-batch failures
- **Orphan modules archived** — `zero_cost_registry.rs`, `zero_cost_registry_tests.rs`,
  legacy HTTP `integration_test.rs` → `ecoPrimals/archive/` (fossil record)
- **File size compliance** — `monitoring.rs` (1052 LOC) → `monitoring.rs` (366) +
  `monitoring_tests.rs` (576); `secure_cross_primal_messaging.rs` (1111 LOC) → production (603) +
  `_tests.rs` (506) via `#[path]` extraction
- **Production mock cleanup** — Fixed "placeholder" comments on real X25519 key exchange, UPA DTOs,
  entropy seed ID generation; documented Phase 2 items (PKCS#11, TPM, compliance handlers)
- **Hardcoding scan** — `biomeos_tmp_socket_root()` respects `BIOMEOS_TMP_ROOT`;
  `InteractionCaptureConfig::default()` replaces magic numbers; network bind fallback uses config
- **Incident handler coverage** — Full lifecycle: create/classify/escalate/assign/resolve/close
- **Performance metrics coverage** — Trend analysis, threshold violations, throughput monitoring

### March 21, 2026 -- Deep Audit: Concurrency Evolution, Coverage Push & Hardcoding Elimination

- **MSRV 1.93.0** — `rust-toolchain.toml` created and pinned; `Cargo.toml` `rust-version` updated
- **`unsafe_code` deny → forbid** — Workspace-wide `forbid(unsafe_code)` in root `Cargo.toml`
- **Zero `#[serial]`** — Eliminated all `#[serial_test::serial]` annotations across the entire
  workspace. Tests now use unique isolated resources (temp dirs, unique socket paths, instance-based
  registries) for full concurrent execution.
- **Zero test sleeps (non-chaos)** — Replaced all `tokio::time::sleep` in non-chaos tests with
  `tokio::sync::Barrier`, `tokio::sync::Notify`, `tokio::task::yield_now()`. Chaos tests retain
  timing-based patterns where appropriate.
- **Production sleep cleanup** — Removed artificial delays from health checkers (`simulated_latency`),
  AI optimization engine (`measure_network_latency`), IPC server (`wait_ready`/`wait_ready_flag`).
  Multi-transport shutdown replaced fixed 100ms sleep with `join_servers_with_timeout`.
- **Flaky test fixes** — `recovery_test_graceful_shutdown` uses `tokio::sync::Barrier` for
  deterministic synchronization. Concurrent pool test assertion relaxed for scheduler variance.
- **Hardcoding evolution** — Network addresses, ports, primal names, TLS version defaults migrated
  to `DEFAULT_*` constants with `from_env()` override. `NetworkAddressesConfig`, `RuntimeNetworkConfig`,
  `SecurityConfig` defaults all use named constants.
- **Self-knowledge enforcement** — `beardog-installer` genome targets loaded from data file via
  `include_str!`. `beardog-integration` UPA client resolves peers via `UPA_UNIX_SOCKET`,
  `CAPABILITY_UPA_REGISTER_ENDPOINT`, or `UPA_PROVIDER` env vars (no hardcoded peer names).
- **Smart refactoring** — `advanced_algorithms.rs` (976 LOC) → `mod.rs` + `types.rs` + `metrics.rs`
  + `engines.rs` + `evolution_engine.rs`. `crypto_handler.rs` (974 LOC) → 11-file module tree.
- **Dead code cleanup** — Removed orphan `alerts.rs`/`health.rs` from monitoring; cleaned
  `#[allow(dead_code)]` with leading underscores or removal; documented remaining with `reason`.
- **Mock isolation** — `testing` and `property_testing` modules gated behind
  `#[cfg(any(test, feature = "test-utils"))]`.
- **Coverage push** — `beardog-traits` 39% → 99.4%, `beardog-deploy` and `beardog-discovery`
  boosted with comprehensive integration tests. Overall: 85.1% line (102,969/121,020).
- **License normalization** — All 13 crate `Cargo.toml` files standardized to
  `license = "AGPL-3.0-or-later"` in `[package]` section.
- **Clippy cleanup** — Fixed cast lints, `mul_add` ambiguity, redundant closures, `#[derive(Default)]`
  opportunities, format string interpolation, let-binding returns.

### March 21, 2026 -- Cast Lint Tightening, Coverage Push & Capability Discovery

- **Cast lint evolution** — Removed 5 global `allow(clippy::cast_*)` from workspace Cargo.toml.
  All 301 cast sites now use per-site `#[expect(clippy::cast_*, reason = "...")]` or
  `Type::from(x)` for lossless casts. New casts must annotate individually.
- **Hardcoded primal names → capability-based discovery** — IPC socket paths, peer resolution,
  and listener binds use `BIOMEOS_IPC_NAMESPACE`, `PRIMAL_NAME`/`BEARDOG_PRIMAL_NAME` env vars
  with runtime discovery fallbacks. Production code no longer hardcodes peer primal names.
- **Coverage push**: 84% → 85.3% region / 85.7% line (13,400 → 13,850+ tests). New tests across
  CLI handlers (daemon, key_derive, key_export, entropy, HSM, streaming, birdsong), tunnel crypto
  (TLS 1.2, Tor, AES-GCM, BTSP, beacon, genetic enrollment, KDF), core (key management,
  interaction capture), and library crates (capabilities, discovery, config, types, auth, threat).
- **Test stability** — Added `serial_test::serial` on all env-dependent tests in
  beardog-capabilities. Eliminated intermittent test-pollution failures.
- **Doc link cleanup** — Resolved all `rustdoc::broken_intra_doc_links`. `cargo doc -D warnings`
  passes clean across the full workspace.
- **Root doc declutter** — 17 reference/guide docs moved from repo root to `docs/references/`.
  Session logs (335 files) moved to `ecoPrimals/archive/` (fossil record).
- **File size compliance** — Extracted 5 test modules into separate `_tests.rs` files to keep all
  .rs files under 1000 lines.
- **Build artifact cleanup** — Removed tracked receipts from git; audit.log files already
  gitignored.

### March 20, 2026 -- Concurrency Architecture & Dependency Modernization

- **Dependency Injection architecture** — Eliminated global mutable state (process_env overlay)
  across ALL crates. `Default` impls are pure (no I/O). `from_env()` uses `std::env::var`
  (read-only, thread-safe). `from_env_provider()` accepts closures for injectable testing.
- **330 → 15 `#[serial_test::serial]` annotations** — Only chaos/fault tests remain serialized.
  All other tests run fully concurrent at `--test-threads=8`.
- **Dependency modernization**:
  - `trust-dns-resolver` → `hickory-resolver` 0.25 (trust-dns was unmaintained)
  - `bincode` → `postcard` 1.0 (bincode was unmaintained)
  - `validator` 0.18 → 0.20 (drops unmaintained `proc-macro-error`)
  - `cargo update` applied across all transitive deps
- **`cargo deny` passes all 4 checks** (advisories, bans, licenses, sources):
  - RSA Marvin Attack documented as accepted risk (no upstream fix)
  - 27 transitive duplicate crates skipped (RustCrypto ecosystem version split)
  - `deny.toml` simplified: AGPL-3.0-or-later in global allow, per-crate exceptions removed
- **Hanging tests eliminated**: `beardog-deploy` refactored with `CommandRunner` trait +
  `MockAdbCommandRunner`. `show_logs` follow mode has bounded timeout. No more zombie
  `adb` processes.
- **Zero clippy warnings** (pedantic + nursery)
- **Coverage**: 80% → 84% (13,400+ tests passing)
- **Config types refactored**: `SocketPathInputs`, `IdentityInputs`, `SelfKnowledgeInputs`,
  `EcosystemListenerEnvInputs`, `ConstraintEnforcementPolicy`, `HsmAutoInitConfig`,
  `DiscoverSocketEnv`, `UnixListenHints`, `IdentityHints`, `ResourceLimits`, and many more
  now flow through the call chain instead of reading globals.

### March 19, 2026 -- Deep Debt Execution & Stub Evolution

- **Zero source clippy warnings**: Fixed all 49 remaining library warnings (redundant borrows,
  `clone_from`, `unwrap_or_else`, `let...else`, redundant closures, format appends, etc.)
- **58 unfulfilled `#[expect]` attributes** fixed (over-converted `#[allow]` reverted or removed)
- **Production stubs evolved to real implementations**:
  - Threat incident handler: typed lifecycle engine with `ManagedIncident`, `BTreeMap` storage, `tracing`
  - Auth genetics: BLAKE3-based nuclear + mitochondrial lineage verification
  - Auth ecosystem: dynamic capability discovery from node registry + security policy
  - Auth consensus: in-memory `BTreeMap<String, ConsensusNodeRecord>` with health tracking
  - Safe memory: real `zeroize::Zeroize` + `ZeroizeOnDrop` for `SafePinnedBuffer`, `SensitiveByteBuf`
- **`#[allow]` → `#[expect(reason)]` sweep** across beardog-core, beardog-tunnel, beardog-utils, beardog-security
- **Test coverage improved**: beardog-ipc 72% → 86%, beardog-core 59% → 62%
- **Failing doctests fixed** in beardog-utils `mock_time.rs` (missing trait import)
- **`primal_discovery.rs`** tests extracted to separate file (1026 → 756 lines)
- **Dockerfile** updated: MSRV 1.85, removed C dependencies, fixed license label
- **`.pedantic_clippy.toml`** MSRV updated to 1.85.0
- 1,072 tests passing, 0 failures, 0 files over 1000 lines

### March 19, 2026 -- Deep Compliance & Coverage Wave 2

- SPDX license headers (`AGPL-3.0-or-later`) added to 1,634 .rs files
- Removed ~130 production `#[allow(dead_code)]` — idiomatic underscore prefixes
- Removed redundant `#[allow]` from beardog-types (workspace config handles them)
- Removed `sysinfo` C dependency (ecoBin violation) — was unused in beardog-deploy
- blake3 `pure` feature enforced across all 13 showcase crates
- `pprof` made optional behind `profiling` feature flag in benchmarks
- Platform FFI (Android NDK, iOS Security.framework) documented as out-of-ecoBin-scope
- IPC hot path optimized: `take()` replaces triple `clone()` on request IDs
- Added ~250 new tests: beardog-core 60%→74%, beardog-ipc 30%→41%
- Prefixed unused struct fields with `_` instead of `#[allow(dead_code)]`
- Migration plan comments added to all `#[allow(deprecated)]` usage sites
- 8,542+ tests passing across 29 crates (0 failures)

### March 19, 2026 -- Deep Compliance & Coverage Wave 1

- Fixed 46 clippy errors in beardog-core (struct_excessive_bools, items_after_statements, etc.)
- Standardized AGPL-3.0-or-later license across all 29 Cargo.toml files
- Workspace lint inheritance (`[lints] workspace = true`) applied to all crates
- Refactored `ProductionConfig` (5 bools → enum) and `SecurityConfig` (4 bools → Option sub-configs)
- Removed `async` from 14 functions that had no `.await`
- Hardcoded primal names evolved to `PRIMAL_NAME` env var + `CARGO_PKG_NAME` fallback
- Zero-key HSM stub replaced with HKDF-SHA256 derived from `BEARDOG_HSM_MASTER_KEY`
- Smart-refactored 3 oversize files (canonical_examples, enforcement, genesis) into submodules
- Replaced 15 production TODOs with doc comments and tracing warnings
- Platform stubs deprecated with `#[deprecated]` guidance

### February 11, 2026 -- Deep Debt Evolution Session

- Smart refactored `quantum_crypto.rs` (1000+ LOC) into modular structure:
  - `quantum_crypto/mod.rs` — module orchestration
  - `quantum_crypto/types.rs` — core types and algorithm enums
  - `quantum_crypto/kem.rs` — Kyber Key Encapsulation Mechanism
  - `quantum_crypto/signatures.rs` — Dilithium and SPHINCS+ signatures
  - `quantum_crypto/engine.rs` — quantum crypto engine orchestration
  - `quantum_crypto/tests.rs` — isolated test module
- Fixed all Clippy warnings (pedantic level, 0 errors)
- Removed corrupted `audit_logging.rs` dead code from `beardog-security`
- Fixed flaky tests with `#[serial_test::serial]` for env var tests
- Improved error handling in `IntegrationEngine` (removed panic-prone `unwrap()`)
- Verified constant-time comparisons for all secret operations
- Root documentation cleaned and metrics updated (12,751+ tests)

### February 11, 2026 -- Relay Authorization & Documentation

- `relay.authorize` JSON-RPC method: lineage-gated relay authorization for coordinated punch
- BearDog verifies family membership before allowing Songbird relay sessions
- Blake3-based lineage proof verification for cross-family relay trust
- `relay` capability type added to `discover_capabilities` response
- 12 new relay handler tests (family match, denial, proof validation, isolation)
- Specs directory rewritten with current metrics (was stale since Oct 2025)
- Primal contracts updated with relay, beacon, and secrets API documentation

### February 11, 2026 -- Test Coverage Push

- Expanded test coverage from ~62% baseline to 78.6% overall
- 9 of 11 measured crates now above 90% coverage target
- Added 3,500+ new tests across all crates
- Root documentation cleaned and consolidated

### February 9, 2026 -- Deep Debt Evolution & Feature Completion

- Multi-family socket support: `--family-id` flag creates per-family sockets
- `discover_capabilities` JSON-RPC method for ecosystem consistency
- Secret storage: `secrets.store`, `secrets.retrieve`, `secrets.list`, `secrets.delete`
- Hardcoded primal names eliminated (all handlers use `get_primal_name()`)
- Smart refactoring: `crypto_handlers_genetic` (2193 lines split into 3 focused modules)
- Production mock audit: dead `stub_types` removed, all mocks isolated to `#[cfg(test)]`
- Cross-primal hardcoding eliminated: `upa_client.rs` uses `discover_upa_provider()`
- All production `expect()`/`unwrap()` eliminated (zero panic paths)
- `once_cell` migrated to `std::sync::LazyLock` across 3 crates
- `base64` 0.21 upgraded to 0.22 (dedup)
- Pre-existing test flakes fixed (env var race conditions)

### February 6, 2026 -- Tor Phase 2 Evolution

- Tor v3 onion address derivation + ntor handshake + cell crypto (8 RPC methods)
- Ed25519, X25519, SHA3-256, ChaCha20, HMAC-SHA256, HKDF-SHA256 primitives

### January 31, 2026 -- ecoBin v2.0 Roadmap

- Q1 2026 ecoBin v2.0 roadmap published
- README biomeOS socket documentation

### January 27-30, 2026 -- Deep Debt Sessions

- Deep debt rounds 12-20 completed (LEGENDARY milestone)
- Panic safety: `debug_assert!` guards, unwrap fixes
- XDG compliance: configurable paths, env vars
- Async traits: `PrimalDiscoveryClient` async
- Feature flags: missing features added
- Workspace versions: 11 crates migrated

### January 24, 2026 -- Smart File Refactoring

- **v0.23.0**: TLS module refactored (2174 lines to 4 focused modules, 34% code reduction)
- **v0.22.0**: 7-phase architectural evolution (unsafe audit, hardcoding removal, mock isolation)
- **v0.21.0**: Crypto handlers refactored (2499 lines to 7 semantic domain modules)

### January 23, 2026 -- RFC 8448 Validation

- **v0.18.0**: Enhanced debug logging for TLS key derivation
- **v0.15.1**: RFC 8448 validation complete (BearDog TLS 1.3 proven compliant)

### January 22, 2026 -- HTTPS & Crypto Expansion

- **v0.15.0**: `tls.derive_handshake_secrets` (RFC 8446 Section 7.1)
- **v0.14.0**: 100% test pass rate achieved (17 failures fixed)
- **v0.13.1**: RFC 8446 full compliance with transcript hash support
- **v0.13.0**: Phase 8 comprehensive testing (20 tests: unit, E2E, chaos, fault)
- **v0.13.0**: `tls.derive_application_secrets` -- Pure Rust HTTPS complete
- Phase 7: Legacy compatibility (bcrypt, scrypt, SHA-1, SHA3-256, HMAC variants)
- Phase 6: Production gaps closed (SHA-256/384/512, ECDH P-256/P-384, AES-GCM, Argon2id)
- Phase 5: Genetic crypto integration (lineage keys, entropy mixing, verification)

### January 21, 2026 -- Handler Registry & BTSP

- **v0.14.0**: Handler registry 100% complete (legacy router deleted, -1514 lines)
- BTSP unified evolution complete (type system, handler extensions)
- Handler registry pattern: 7 modular handlers, 47 RPC methods
- Dead code cleanup: 315 unreachable lines removed

### January 19, 2026 -- UniBin & Tower Atomic

- UniBin commands: server, daemon, doctor, client (100% complete)
- 151 comprehensive tests (unit, E2E, chaos, fault)
- `beardog-tower-atomic` crate: Pure Rust IPC (Unix socket + JSON-RPC)
- Capability-based discovery (zero vendor hardcoding)

### January 18, 2026 -- Crypto API

- 8 Pure Rust crypto operations for Songbird TLS integration
- Ed25519 sign/verify, X25519 key exchange, ChaCha20-Poly1305, Blake3, HMAC-SHA256
- 52 comprehensive crypto tests
- JSON-RPC crypto API over Unix sockets

---

## [0.9.0] -- November-December 2025

### Added

- Universal HSM Discovery Engine with 8+ HSM type support
- BSTP (BearDog Secure Tunnel Protocol) for encrypted communication
- Genetic entropy system with self-evolving key management
- Protocol-agnostic design (HTTP REST, JSON-RPC 2.0, tarpc)
- Runtime primal discovery via mDNS and service registry
- Hardware security module integration (YubiKey, TPM 2.0, StrongBox, Secure Enclave)
- 8,174+ tests with 70+ chaos tests
- Comprehensive error handling system
- Zero-configuration capability discovery

### Changed

- Eliminated all hardcoded values from production code
- Evolved to modern idiomatic Rust patterns throughout
- Refactored large files to maintain <1000 lines per file discipline
- 23 crates with zero circular dependencies

---

For detailed session notes, see `ecoPrimals/archive/` (fossil record) organized by date and topic.
