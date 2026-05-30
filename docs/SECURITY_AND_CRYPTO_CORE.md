# SecureVault — Security Review, `upgrade-kdf` Fix, and the Rust `crypto-core` Migration

> **Purpose of this document.** A complete, self-contained record of the work done in this
> session: the full security review (all findings), the one bug that was actually fixed
> (`upgrade-kdf`) with every code change in full, the architecture decision to unify client
> crypto behind a single Rust core, the entire `crypto-core` crate source (copy-pasteable),
> the golden-vector test harness, what is **proven**, what is **pending/blocked**, and the
> complete step-by-step plan to finish replacing per-client crypto with the Rust core.
>
> Date: 2026-05-29. Repo: `/Users/mondaltanay/Projects/Password-Manager`.

---

## Table of contents

1. [System overview](#1-system-overview)
2. [Security review — all findings](#2-security-review--all-findings)
   - [2.1 Backend (Java/Spring)](#21-backend-javaspring)
   - [2.2 Web app & browser extension](#22-web-app--browser-extension)
   - [2.3 Mobile (Kotlin Multiplatform)](#23-mobile-kotlin-multiplatform)
   - [2.4 Verified OK](#24-verified-ok-no-action)
3. [The fix that was implemented: `upgrade-kdf`](#3-the-fix-that-was-implemented-upgrade-kdf)
   - [3.1 Why it was Critical](#31-why-it-was-critical)
   - [3.2 Backend changes (full code)](#32-backend-changes-full-code)
   - [3.3 Web client changes (full code)](#33-web-client-changes-full-code)
   - [3.4 How the flow works now](#34-how-the-flow-works-now)
4. [Architecture decision: one Rust crypto core](#4-architecture-decision-one-rust-crypto-core)
5. [The current v2 crypto format (the spec to preserve)](#5-the-current-v2-crypto-format-the-spec-to-preserve)
6. [The `crypto-core` crate — full source](#6-the-crypto-core-crate--full-source)
7. [Golden test vectors — full source](#7-golden-test-vectors--full-source)
8. [Verification results](#8-verification-results)
9. [What's done / what's pending](#9-whats-done--whats-pending)
10. [Complete replacement plan (all steps)](#10-complete-replacement-plan-all-steps)
11. [File inventory & commands](#11-file-inventory--commands)
12. [Evolving the cryptography (how to update crypto safely)](#12-evolving-the-cryptography-how-to-update-crypto-safely)
13. [Golden vectors explained](#13-golden-vectors-explained)
14. [Threat model — how safe is the vault from an attacker](#14-threat-model--how-safe-is-the-vault-from-an-attacker)
15. [Making it unbreakable: weak password + full server/DB breach](#15-making-it-unbreakable-weak-password--full-serverdb-breach)
16. [Storing the Secret Key (end-user UX)](#16-storing-the-secret-key-end-user-ux)
17. [Competitive security comparison (Bitwarden / 1Password / Proton Pass)](#17-competitive-security-comparison-bitwarden--1password--proton-pass)

---

## 1. System overview

SecureVault is a **zero-knowledge** password manager with three components:

| Component | Stack | Location |
|-----------|-------|----------|
| Backend API | Java 17 / Spring Boot | `src/main/java/com/securevault/` |
| Web app + browser extension | React + TypeScript (Vite) | `web/` |
| Mobile app | Kotlin Multiplatform (Android + iOS) | `mobile/` |

**Zero-knowledge model.** The master password never leaves the device. The client derives
two things from it with Argon2id:

```
master password ──Argon2id(password, authSalt,       params)──▶ authHash  ──▶ sent to server (auth)
                └─Argon2id(password, encryptionSalt,  params)──▶ KEK       ──▶ stays on device
```

- **authHash** authenticates the user. The server re-hashes it with PBKDF2-HMAC-SHA256
  (600k iterations) + a server salt and stores *that* (`serverSideHash`).
- **KEK** (key-encryption key) never leaves the device. It AES-GCM-unwraps the
  **`wrappedVaultKey`** to recover the random 32-byte **vault key**, which encrypts entries.

The server only ever stores: `serverSideHash(authHash)`, the opaque `wrappedVaultKey`, the
salts, and the **KDF parameters** (`kdfIterations / kdfMemory / kdfParallelism`). It never
sees the password, KEK, or vault key.

---

## 2. Security review — all findings

Severity scale: **Critical / High / Medium / Low**. Each finding lists `file:line`. The
core crypto design is sound; the serious issues are an authorization gap in the backend and
the entire iOS crypto/storage layer, plus the browser extension.

### 2.1 Backend (Java/Spring)

#### CRITICAL

- **C1 — `POST /api/v1/auth/upgrade-kdf` is an account-takeover / vault-lockout primitive.**
  `AuthController.java:222`, `AuthService.java:444`. Unlike `change-password` and
  `delete-account`, it was **not `@RequireSudo`** and never verified the current password.
  With only an access token it overwrites `passwordHash`, `passwordSalt`, `wrappedVaultKey`,
  KDF params, and bumps `passwordUpdatedAt` (which invalidates the user's other sessions via
  `JwtAuthenticationFilter.java:112`). **FIXED — see §3.**

- **C2 — `UpgradeKdfRequest` had no KDF bounds → KDF-downgrade.** `UpgradeKdfRequest.java`.
  Only `@NotNull`, unlike `RegisterRequest` (iterations 1–100, memory 8192–1048576,
  parallelism 1–16). An attacker (via C1) could set `iterations=1, memory=8`, making the
  vault offline-brute-forceable. **FIXED — see §3.**

#### HIGH

- **H1 — CORS allows credentials with localhost origins in prod.** `CorsConfig.java:17`
  (`setAllowCredentials(true)` + localhost origin-patterns, no profile separation).
- **H2 — `X-Forwarded-For` first hop trusted → rate-limit/lockout bypass.**
  `ClientIpResolver.java:16` returns the client-controlled left-most XFF when
  `app.proxy.trusted=true`; all IP rate limiting keys off it.
- **H3 — Sudo token accepted via query/body param.** `SudoAspect.java:33` reads a
  `sudo_token` request parameter as a fallback → leaks into logs/history/Referer.
  Should be header-only (`X-Sudo-Token`).
- **H4 — TOTP brute-force surface.** `AuthService.java:243`; the per-challenge cap of 5 is
  bypassable by re-issuing a challenge (re-submit password); no durable per-user TOTP-verify
  lock.

#### MEDIUM

- **M1 — CSRF disabled with cookie-based refresh.** `SecurityConfig.java:50`; only
  `SameSite=Strict` protects `/refresh`. Add an origin check / defense-in-depth.
- **M2 — PII & debug leakage in logs.** `AuthService.java:176`
  (`LOGIN_DEBUG: userExists=...`); `AuthController` logs full emails at INFO;
  `PendingLoginChallengeStore.java:44`.
- **M3 — User enumeration via `prelogin` timing.** `AuthService.java:138` (real DB salt
  lookup vs random salt generation); `login` is timing-hardened but `prelogin` is not.
- **M4 — Refresh-reuse detection over-fires.** `AuthService.java:285`; a replayed stale
  token wipes all sessions (DoS-able).
- **M5 — Denylist TTL can be 0.** `JwtAuthenticationFilter.java:138` (Redis rejects
  non-positive EX near token expiry).

#### LOW

- Default Argon2id `t=4 / 64MB / 4` is on the low end of OWASP guidance
  (`EncryptionConstants.java:7`).
- HSTS only in `prod` profile; `REQUIRE_SSL` defaults false; no fail-fast on missing TLS
  (`SecurityConfig.java:38`).
- `SudoService.revokeAllForUser` uses a blocking `KEYS` scan (`SudoService.java:41`).

### 2.2 Web app & browser extension

The web app's core crypto is well-implemented (Argon2id, AES-GCM, random IVs from CSPRNG,
no IV reuse, no `Math.random`, no XSS sinks). The serious problems are in the **extension**.

#### CRITICAL

- **W-C1 — Content script injects into every origin incl. plaintext HTTP.**
  `web/extension/manifest.json:24` `"matches": ["http://*/*", "https://*/*"]` + autofill
  (`content.ts:107`) → credentials can be filled into `http://` pages (MITM) and the script
  runs on all origins. Drop `http://*`, restrict matches, never autofill on insecure origins.
- **W-C2 — Extension persists the refresh token in `chrome.storage.local`.**
  `storage.ts:32`, `background.ts:81`. `chrome.storage.local` is unencrypted on disk and
  survives restarts; the long-lived refresh token sits there in plaintext (the web app
  correctly uses an httpOnly cookie). Use `chrome.storage.session`, or don't persist it.

#### HIGH

- **W-H1 — Weak domain matching for autofill.** `background.ts:41` naive `www.`-strip, no
  scheme/port check (reinforces W-C1).
- **W-H2 — No origin/sender validation on extension messages.** `background.ts:49`; any
  frame can request decrypted entries / write clipboard. Validate `sender.id`.

#### MEDIUM

- **W-M1 — No client-side KDF floor.** `VaultContext.tsx:116`, trusts server/prelogin KDF
  params verbatim; a malicious/MITM server could return `iterations:1`.
- **W-M2 — Weak/missing auto-lock.** `useAutoLock.ts:22` no `visibilitychange`/`blur` lock;
  the **extension has no auto-lock at all**.
- **W-M3 — Master password crosses popup→background as a raw value.** `script.ts:108`,
  `background.ts:94`.

#### LOW

- Web CSP allows `style-src 'unsafe-inline'` + loads Google Fonts not in policy
  (`nginx.conf:11`, `index.html:7`); nginx has no HSTS.
- Extension popup CSP lacks `default-src`/`connect-src` (`manifest.json:6`).

### 2.3 Mobile (Kotlin Multiplatform)

Android crypto is broadly correct (Argon2id + AES-GCM matching web). **iOS is broken.**

#### CRITICAL

- **M-C1 — iOS AES-GCM provides no authentication.** `CryptoEngine.ios.kt:88,133`,
  `IosEntryEncryptor.kt`. Uses `CCCrypt(..., kCCOptionGCM, ...)` — the one-shot `CCCrypt`
  API does **not** implement authenticated GCM (real GCM needs `CCCryptorCreateWithMode` /
  `CCCryptorGCMFinalize`). No tag is produced or verified; the appended `+16` bytes are
  garbage and `unwrapVaultKey` ignores the `CCCrypt` status. iOS ciphertext is effectively
  unauthenticated and tamperable. **Fix: reimplement with CryptoKit `AES.GCM`.**
- **M-C2 — iOS KEK uses PBKDF2 with attacker-influenced low iterations.**
  `CryptoEngine.ios.kt:46`, `IosEntryEncryptor.kt:192`, `AuthRepositoryImpl.kt:91`. iOS
  derives the KEK with `kCCPBKDF2` (Android uses Argon2id) and the iteration count is
  `kdfIterations` (default **4**, from the server). PBKDF2 @ 4 iterations is trivially
  crackable. Vaults are also cross-platform incompatible. **Fix: Argon2id matching Android.**
- **M-C3 — iOS has no secure storage for tokens/keys.** `SessionManager.kt:1`. It lives in
  `commonMain` but imports Android-only `EncryptedSharedPreferences`/`MasterKey`/`Context`.
  There is **no iOS Keychain implementation** — access/refresh tokens, salts, and wrapped
  vault key have no working secure store on iOS. **Fix: `expect/actual` Keychain on iOS.**

#### HIGH

- **M-H1 — iOS ships `http://localhost:8080` as the API base.** `iosMain/di/AppModule.kt:14`
  (cleartext, non-prod). (Android correctly uses `https://vault.tanay.pro`.)
- **M-H2 — iOS `IosEntryEncryptor.decrypt` is a broken stub.** `IosEntryEncryptor.kt:101`
  returns empty fields; `encrypt` uses `toString()` not JSON — non-interoperable/data-losing.
- **M-H3 — No client-side KDF floor / trusts server params.** `AuthRepositoryImpl.kt:91`.
- **M-H4 — No TLS certificate pinning.** `SecureVaultApi.kt:388`; fixed host, no pinning.

#### MEDIUM

- **M-M1 — Local SQLCipher key not auth-gated (Android).** `DatabaseKeyManager.kt:60`;
  Keystore master key has no `setUserAuthenticationRequired`, recoverable on a rooted
  device. Title/username cached **unencrypted** (`CachedVaultRepository.kt:156`).
- **M-M2 — Weak Android auto-lock.** `AndroidEntryEncryptor.kt:29`; 5-min `Handler`,
  doesn't survive backgrounding/process death.
- **M-M3 — `isUnauthorized` substring-matches exception text.** `SecureVaultApi.kt:322`.

#### LOW

- Cleartext permitted for `10.0.2.2`/`localhost` in `network_security_config.xml` (dev).
- ProGuard keeps the whole app package, shrink disabled (`proguard-rules.pro:19`).
- iOS has no `FLAG_SECURE` screenshot-protection equivalent.

### 2.4 Verified OK (no action)

IDOR checks on vault entries & devices are correct; no SQL injection; JWT uses separate
derived HMAC keys for access vs refresh (no algorithm confusion); 2FA secret at rest is
AES-256-GCM with a random IV; constant-time hash compare with dummy-hash timing hardening
on `login`; `change-password` correctly revokes all refresh tokens; web access token in
memory + refresh in httpOnly cookie; no XSS sinks; CSPRNG + rejection sampling in the
password generator; Android `allowBackup=false`, only the launcher activity exported, no
hardcoded secrets; SHA-1 only for HIBP k-anonymity (required).

---

## 3. The fix that was implemented: `upgrade-kdf`

Only **C1 + C2** were fixed in this session (the user prioritized them). All other findings
above remain open.

### 3.1 Why it was Critical

`upgrade-kdf` is a legitimate feature: a **lazy KDF migration**. When the app's default KDF
strength is raised, existing accounts keep their old (weaker) params. On unlock, the web
client checks "are my params weaker than today's default?" and if so re-derives the KEK with
stronger params, re-wraps the vault key, and pushes the new wrapped key + params to the
server (`web/src/context/VaultContext.tsx:127`).

The endpoint mutates `passwordHash` and `wrappedVaultKey`, so it **must** be
authorization-gated. It was not:

- **Not `@RequireSudo`** and no current-password check → a stolen access token could rotate
  the auth hash and wrapped vault key (account takeover / vault lockout).
- **No KDF bounds** → the same mechanism could be used in reverse to *downgrade* params to
  `iterations=1, memory=8`, deliberately weakening the vault for offline brute force.

The benefit of the feature (when secured): it retroactively strengthens the Argon2id cost —
the only wall between a stolen database and a cracked vault — for legacy accounts, silently,
without forcing a password reset. It only helps against **offline attack after a DB breach**
(not online attacks, and not for already-strong passwords).

### 3.2 Backend changes (full code)

**File: `src/main/java/com/securevault/controller/AuthController.java`** — added `@RequireSudo`
to the endpoint (the `RequireSudo` import was already present, used by `change-password` /
`delete-account`). Final method:

```java
    @RequireSudo
    @PostMapping("/upgrade-kdf")
    public ResponseEntity<ApiResponse<String>> upgradeKdf(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody com.securevault.dto.UpgradeKdfRequest request) {
        UUID userId = UserUtils.getUserId(userDetails);
        log.info("KDF parameter upgrade request for user: {}", userId);
        authService.upgradeKdf(userId, request);
        return ResponseEntity.ok(ApiResponse.success("KDF parameters upgraded successfully", ""));
    }
```

> The `@RequireSudo` aspect (`SudoAspect.java`) matches any method with this annotation and
> requires a valid, single-use sudo token (header `X-Sudo-Token`). A sudo token is only
> issued by `POST /api/v1/auth/sudo` after the user re-authenticates with their current
> password (`authService.verifyPassword`).

**File: `src/main/java/com/securevault/dto/UpgradeKdfRequest.java`** — added bounds matching
`RegisterRequest`. Full final file:

```java
package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UpgradeKdfRequest {

    @NotBlank(message = "Auth hash is required")
    @Size(max = 1024, message = "Auth hash must not exceed 1024 characters")
    @JsonProperty("authHash")
    private String authHash;

    @NotBlank(message = "Wrapped vault key is required")
    @Size(max = 100000, message = "Wrapped vault key must not exceed 100KB")
    @JsonProperty("wrappedVaultKey")
    private String wrappedVaultKey;

    @NotNull(message = "KDF iterations is required")
    @Min(value = 1, message = "KDF iterations must be at least 1")
    @Max(value = 100, message = "KDF iterations must not exceed 100")
    @JsonProperty("kdfIterations")
    private Integer kdfIterations;

    @NotNull(message = "KDF memory is required")
    @Min(value = 8192, message = "KDF memory must be at least 8MB")
    @Max(value = 1048576, message = "KDF memory must not exceed 1GB")
    @JsonProperty("kdfMemory")
    private Integer kdfMemory;

    @NotNull(message = "KDF parallelism is required")
    @Min(value = 1, message = "KDF parallelism must be at least 1")
    @Max(value = 16, message = "KDF parallelism must not exceed 16")
    @JsonProperty("kdfParallelism")
    private Integer kdfParallelism;
}
```

> **Not compiled in this environment** (no Maven/JRE available). The changes are trivial and
> mirror already-compiling code in the same packages.

### 3.3 Web client changes (full code)

Adding `@RequireSudo` is a **breaking change** for the web app, which called `upgrade-kdf`
with no sudo token. Two files changed.

**File: `web/src/api/auth.ts`** — `upgradeKdf` now accepts an optional `sudoToken` and sends
it as the `X-Sudo-Token` header (mirrors `changePassword`/`disable2FA`/`deleteDevice`):

```ts
export function upgradeKdf(data: UpgradeKdfRequest, sudoToken?: string) {
  const headers: Record<string, string> = {}
  if (sudoToken) {
    headers['X-Sudo-Token'] = sudoToken
  }
  return apiClient<void>('/auth/upgrade-kdf', {
    method: 'POST',
    headers,
    body: JSON.stringify(data),
  })
}
```

**File: `web/src/context/VaultContext.tsx`** — the background KDF upgrade (which runs right
after `unlock(password)`, while the plaintext password is in memory) now derives the
**current** auth hash with the **old** KDF params (so the server's `verifyPassword` matches
the stored hash), requests a sudo token, and passes it. The relevant block (inside the
`unlock` callback, the `if (currentMemory < DEFAULT_KDF_MEMORY)` branch):

```ts
            const newWrapped = await wrapVaultKey(newKek, vaultKeyDerived)

            // Obtain a sudo token by re-deriving the current auth hash with the
            // existing (pre-upgrade) KDF params so the server can verify it.
            const currentAuthHash = await derivePasswordHash(
              password,
              material.authSalt,
              material.kdfIterations,
              material.kdfMemory,
              material.kdfParallelism
            )
            const sudo = await requestSudo(currentAuthHash)

            await upgradeKdf({
              authHash: newAuthHash,
              wrappedVaultKey: newWrapped,
              kdfIterations: DEFAULT_KDF_ITERATIONS,
              kdfMemory: DEFAULT_KDF_MEMORY,
              kdfParallelism: DEFAULT_KDF_PARALLELISM,
            }, sudo.sudoToken)
```

> `requestSudo` and `derivePasswordHash` were already imported in `VaultContext.tsx`. The
> exact same `derivePasswordHash(...) → requestSudo` sequence already exists in this file's
> `changePassword` flow. **Not type-checked here** (no Node at the time of editing).

**Other clients:** the **mobile app** and **browser extension** do **not** call
`upgrade-kdf` — no changes needed.

### 3.4 How the flow works now

1. User enters master password → `unlock(password)`.
2. If stored `kdfMemory < DEFAULT_KDF_MEMORY`, the background upgrade fires.
3. It derives `currentAuthHash` from the in-memory password using the **old** params.
4. `POST /auth/sudo {authHash: currentAuthHash}` → server `verifyPassword` → returns a
   single-use `sudoToken`.
5. `POST /auth/upgrade-kdf` with `X-Sudo-Token: sudoToken` and the new params/wrapped key.
6. Server `@RequireSudo` aspect validates+consumes the token, then `upgradeKdf` persists.

This is **seamless** (no extra prompt — it reuses the just-typed password) and wrapped in
try/catch, so failure is logged and retried on the next unlock.

#### Known follow-up (NOT done)
`AuthService.upgradeKdf` still does **not** call `refreshTokenRepository.deleteByUserId(...)`
(unlike `changePassword`), yet it bumps `passwordUpdatedAt`. Decide deliberately whether
rotating the auth hash mid-session should also revoke refresh tokens. Also H3 (sudo token
via query param) remains open.

---

## 4. Architecture decision: one Rust crypto core

**Problem.** Web (TS), Android (Kotlin/JCA + argon2kt), and iOS (CommonCrypto) each have
their own crypto. They have drifted — most severely, iOS uses PBKDF2 + non-authenticated GCM
+ `toString()` serialization while web/Android use Argon2id + real GCM + JSON. In a
zero-knowledge vault these client implementations **must be byte-for-byte interoperable**.

**Two distinct crypto domains (do not conflate):**

1. **Client vault crypto** (web + Android + iOS) — Argon2id, AES-GCM, envelopes,
   serialization. Must be identical across platforms. *This* is what the Rust core unifies.
2. **Server crypto** — `serverSideHash` (PBKDF2 peppering), JWT signing, 2FA-at-rest. This
   is intentionally different and **must NOT** share code with clients — sharing it would
   break zero-knowledge. **Leave the server alone.**

**Why not consolidate `upgrade-kdf` into `change-password`?** Considered and rejected: they
look similar but have opposite semantics. `change-password` runs `checkPasswordHistory`
(would *reject* the same password), force-revokes all sessions, and records password history
— all wrong for a silent same-password KDF upgrade. Merging them would mean a boolean flag
forking one method into two behaviors, which is *harder* to audit for security code. Keep
them separate.

**Chosen direction (the "gold standard").** A single **Rust core** implementing the client
vault crypto, compiled to **WASM for web** (via `wasm-bindgen`/`wasm-pack`) and to **native
for mobile** (via **UniFFI** → Kotlin + Swift; `cargo-ndk` for Android `.so`, XCFramework
for iOS). Then there is literally one implementation and drift becomes impossible. Drift is
enforced-against by **golden test vectors** that every platform must reproduce.

**Make-or-break constraint:** the Rust core must be **bug-for-bug compatible with the
existing v2 format** so existing vaults need no migration (web & Android already use the
target primitives; iOS is a fix, not a migration).

---

## 5. The current v2 crypto format (the spec to preserve)

`encryptionVersion = 2` (`EncryptionConstants.CURRENT_ENCRYPTION_VERSION`). Defaults:
`iterations = 4`, `memory = 65536 KiB (64 MB)`, `parallelism = 4`, output 32 bytes.

### 5.1 KDF — Argon2id (the salt asymmetry, the #1 interop risk)

| Use | Algorithm | Salt input encoding | Output |
|-----|-----------|---------------------|--------|
| authHash | Argon2id v0x13 | **salt as UTF-8 string bytes** (`new TextEncoder().encode(salt)`) | 32 bytes → base64 |
| KEK | Argon2id v0x13 | **base64-decode(salt) → raw bytes** | 32 bytes (raw) |

> Source: `web/src/crypto/argon2.ts`. `derivePasswordHash` uses the salt *string*;
> `deriveKek` base64-decodes it. The core replicates **both** per call site. Android's
> authHash path must be confirmed to match the web string-salt behavior (open item).

### 5.2 AEAD — AES-256-GCM

`nonce = 12 random bytes`, `tag = 128 bits`, tag **appended** to ciphertext (`ct||tag` —
the default for WebCrypto, JCA, and RustCrypto). No AAD today.

### 5.3 The three envelope layouts (all in use)

| # | Name | Layout | Where | Synced |
|---|------|--------|-------|--------|
| A | Wrapped key | `base64( nonce[12] ‖ ct ‖ tag )` (one string) | `web/src/crypto/vaultKey.ts`, Android `wrapVaultKey` | yes |
| B | Entry | `encrypted_data = "v1:" + base64(ct‖tag)` **and a separate** `iv = base64(nonce)` | `web/src/crypto/entries.ts`, Android `encrypt` | yes |
| C | Local field | `"v1:" + base64( nonce[12] ‖ ct ‖ tag )` | Android `encryptField` (Room cache only) | **no** |

> Envelope **B keeps the nonce in its own `iv` field and does NOT prepend it** — different
> from A and C. The `"v1:"` prefix is on B and C, absent on A. Getting B wrong silently
> corrupts every entry.

### 5.4 Entry plaintext serialization

The plaintext inside envelope B is JSON. Android uses
`Json.encodeToString(VaultEntry.serializer(), entry)`; web builds the object in
`VaultEntryForm.tsx`. For cross-platform field interop the JSON shape must be identical —
the core should own canonical (stable-key-order) JSON (open item; today the core treats
plaintext as an opaque string).

---

## 6. The `crypto-core` crate — full source

Location: `crypto-core/`. Pure Rust core (no bindings yet). **Compiles, clippy-clean, tests
pass** (see §8).

### 6.1 `crypto-core/Cargo.toml`

```toml
[package]
name = "securevault-crypto-core"
version = "0.1.0"
edition = "2021"
description = "Single-source client vault crypto for SecureVault (v2 format). Compiles to wasm (web) and native (Android/iOS)."
license = "MIT"

[lib]
# rlib: native unit + integration tests. cdylib: wasm / Android JNI. staticlib: iOS.
crate-type = ["rlib", "cdylib", "staticlib"]

[dependencies]
argon2 = "0.5"
aes-gcm = "0.10"
base64 = "0.22"
getrandom = "0.2"
zeroize = "1"

# wasm needs getrandom backed by Web Crypto.
[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }

[dev-dependencies]
serde_json = "1"
```

### 6.2 `crypto-core/src/error.rs`

```rust
use core::fmt;

/// Opaque crypto error. Messages are intentionally generic — never embed secrets,
/// and do not distinguish "wrong key" from "tampered data" (both -> `DecryptionFailed`).
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidParams(&'static str),
    InvalidKeyLength,
    InvalidInput(&'static str),
    Base64,
    Kdf,
    Encrypt,
    DecryptionFailed,
    Rng,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidParams(m) => write!(f, "invalid KDF parameters: {m}"),
            CryptoError::InvalidKeyLength => write!(f, "invalid key length"),
            CryptoError::InvalidInput(m) => write!(f, "invalid input: {m}"),
            CryptoError::Base64 => write!(f, "base64 decode failed"),
            CryptoError::Kdf => write!(f, "key derivation failed"),
            CryptoError::Encrypt => write!(f, "encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "decryption failed"),
            CryptoError::Rng => write!(f, "RNG failure"),
        }
    }
}

impl std::error::Error for CryptoError {}
```

### 6.3 `crypto-core/src/params.rs`

```rust
use crate::error::CryptoError;

/// Argon2id cost parameters. `memory_kib` is in KiB (65536 == 64 MB).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub iterations: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
}

/// Current default — matches web `DEFAULT_KDF_*` and server `EncryptionConstants`.
pub const DEFAULT_PARAMS: KdfParams = KdfParams {
    iterations: 4,
    memory_kib: 65536,
    parallelism: 4,
};

/// Absolute floor for *accepting* server-supplied params (OWASP-ish minimum).
/// NOTE: this is only enforced by [`validate_params`], which the app calls when
/// deciding whether to trust prelogin/auth-response params. The `derive_*` functions
/// do NOT enforce it — they must reproduce ANY params so legacy vaults still decrypt.
pub const MIN_PARAMS: KdfParams = KdfParams {
    iterations: 2,
    memory_kib: 19456, // 19 MiB
    parallelism: 1,
};

/// Reject parameters weaker than [`MIN_PARAMS`]. Call this on params received from the
/// server before using them, to block a KDF-downgrade attack.
pub fn validate_params(p: &KdfParams) -> Result<(), CryptoError> {
    if p.iterations < MIN_PARAMS.iterations {
        return Err(CryptoError::InvalidParams("iterations below minimum"));
    }
    if p.memory_kib < MIN_PARAMS.memory_kib {
        return Err(CryptoError::InvalidParams("memory below minimum"));
    }
    if p.parallelism < MIN_PARAMS.parallelism {
        return Err(CryptoError::InvalidParams("parallelism below minimum"));
    }
    Ok(())
}
```

### 6.4 `crypto-core/src/kdf.rs`

```rust
use crate::error::CryptoError;
use crate::params::KdfParams;
use argon2::{Algorithm, Argon2, Params, Version};

/// Raw Argon2id -> 32 bytes. Version 0x13 (19), matching hash-wasm (web) and
/// argon2kt (Android) defaults. `salt` is passed through verbatim — callers decide
/// the salt's byte encoding (UTF-8 string bytes for authHash, base64-decoded for KEK).
pub(crate) fn argon2id_raw(
    password: &[u8],
    salt: &[u8],
    p: &KdfParams,
) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(p.memory_kib, p.iterations, p.parallelism, Some(32))
        .map_err(|_| CryptoError::InvalidParams("argon2 params out of range"))?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    hasher
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}
```

### 6.5 `crypto-core/src/aead.rs`

```rust
use crate::error::CryptoError;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

pub(crate) const NONCE_LEN: usize = 12;

/// AES-256-GCM encrypt. Returns `ciphertext || tag` (tag appended, 16 bytes) —
/// the same layout as WebCrypto, JCA, and RustCrypto.
pub(crate) fn encrypt(key: &[u8], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| CryptoError::Encrypt)
}

/// AES-256-GCM decrypt of `ciphertext || tag`. Verifies the tag; any failure
/// (wrong key or tampering) -> `DecryptionFailed`.
pub(crate) fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidInput("nonce must be 12 bytes"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}
```

### 6.6 `crypto-core/src/lib.rs`

```rust
//! SecureVault crypto-core — single-source client vault crypto (v2 format).
//!
//! Reproduces the exact format used today by the web app (`web/src/crypto/*`) and the
//! Android client (`AndroidEntryEncryptor.kt`) so existing vaults need no migration.
//! See `crypto-core/DESIGN.md` and the golden vectors in `test-vectors/`.
//!
//! Three envelope layouts exist in the v2 system:
//!   A. wrapped key:  base64( nonce[12] || ct||tag )            -> [`wrap_vault_key`]
//!   B. entry:        "v1:"+b64(ct||tag) + a SEPARATE iv field  -> [`encrypt_entry`]
//!   C. local field:  "v1:"+b64( nonce[12] || ct||tag )         -> [`encrypt_field`]

mod aead;
mod error;
mod kdf;
mod params;

pub use error::CryptoError;
pub use params::{validate_params, KdfParams, DEFAULT_PARAMS, MIN_PARAMS};

use aead::NONCE_LEN;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use zeroize::Zeroize;

const VERSION_PREFIX: &str = "v1:";
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;

fn b64e(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn b64d(s: &str) -> Result<Vec<u8>, CryptoError> {
    STANDARD.decode(s).map_err(|_| CryptoError::Base64)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| CryptoError::Rng)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// KDF
// ---------------------------------------------------------------------------

/// authHash = Argon2id(password, salt AS UTF-8 STRING BYTES). Returns base64(32 bytes).
pub fn derive_auth_hash(password: &str, salt_str: &str, p: &KdfParams) -> Result<String, CryptoError> {
    let mut h = kdf::argon2id_raw(password.as_bytes(), salt_str.as_bytes(), p)?;
    let out = b64e(&h);
    h.zeroize();
    Ok(out)
}

/// KEK = Argon2id(password, BASE64-DECODE(salt)). Returns the raw 32-byte key.
/// Caller owns the returned key material and is responsible for zeroizing it.
pub fn derive_kek(password: &str, salt_b64: &str, p: &KdfParams) -> Result<Vec<u8>, CryptoError> {
    let mut salt = b64d(salt_b64)?;
    let h = kdf::argon2id_raw(password.as_bytes(), &salt, p);
    salt.zeroize();
    Ok(h?.to_vec())
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Fresh random 32-byte vault key.
pub fn generate_vault_key() -> Result<Vec<u8>, CryptoError> {
    Ok(random_bytes::<KEY_LEN>()?.to_vec())
}

/// Fresh random 16-byte salt, base64-encoded.
pub fn generate_salt() -> Result<String, CryptoError> {
    Ok(b64e(&random_bytes::<SALT_LEN>()?))
}

// ---------------------------------------------------------------------------
// Envelope A — wrapped vault key: base64( nonce || ct||tag )
// ---------------------------------------------------------------------------

pub(crate) fn wrap_vault_key_with_nonce(
    kek: &[u8],
    vault_key: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<String, CryptoError> {
    let ct = aead::encrypt(kek, nonce, vault_key)?;
    let mut combined = Vec::with_capacity(NONCE_LEN + ct.len());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(&ct);
    Ok(b64e(&combined))
}

pub fn wrap_vault_key(kek: &[u8], vault_key: &[u8]) -> Result<String, CryptoError> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    wrap_vault_key_with_nonce(kek, vault_key, &nonce)
}

pub fn unwrap_vault_key(kek: &[u8], wrapped_b64: &str) -> Result<Vec<u8>, CryptoError> {
    let combined = b64d(wrapped_b64)?;
    if combined.len() <= NONCE_LEN {
        return Err(CryptoError::InvalidInput("wrapped key too short"));
    }
    let (nonce, ct) = combined.split_at(NONCE_LEN);
    aead::decrypt(kek, nonce, ct)
}

// ---------------------------------------------------------------------------
// Envelope B — entry: encrypted_data = "v1:"+b64(ct||tag), separate iv = b64(nonce)
// ---------------------------------------------------------------------------

/// Entry ciphertext: the nonce is carried in its OWN `iv` field, NOT prepended.
pub struct EntryCiphertext {
    pub encrypted_data: String,
    pub iv: String,
}

pub(crate) fn encrypt_entry_with_nonce(
    vault_key: &[u8],
    plaintext_json: &str,
    nonce: &[u8; NONCE_LEN],
) -> Result<EntryCiphertext, CryptoError> {
    let ct = aead::encrypt(vault_key, nonce, plaintext_json.as_bytes())?;
    Ok(EntryCiphertext {
        encrypted_data: format!("{VERSION_PREFIX}{}", b64e(&ct)),
        iv: b64e(nonce),
    })
}

pub fn encrypt_entry(vault_key: &[u8], plaintext_json: &str) -> Result<EntryCiphertext, CryptoError> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    encrypt_entry_with_nonce(vault_key, plaintext_json, &nonce)
}

pub fn decrypt_entry(vault_key: &[u8], c: &EntryCiphertext) -> Result<String, CryptoError> {
    let raw = c.encrypted_data.strip_prefix(VERSION_PREFIX).unwrap_or(&c.encrypted_data);
    let ct = b64d(raw)?;
    let nonce = b64d(&c.iv)?;
    let pt = aead::decrypt(vault_key, &nonce, &ct)?;
    String::from_utf8(pt).map_err(|_| CryptoError::InvalidInput("plaintext not utf-8"))
}

// ---------------------------------------------------------------------------
// Envelope C — local field (Android cache parity): "v1:"+b64( nonce || ct||tag )
// ---------------------------------------------------------------------------

pub(crate) fn encrypt_field_with_nonce(
    vault_key: &[u8],
    plaintext: &str,
    nonce: &[u8; NONCE_LEN],
) -> Result<String, CryptoError> {
    let ct = aead::encrypt(vault_key, nonce, plaintext.as_bytes())?;
    let mut combined = Vec::with_capacity(NONCE_LEN + ct.len());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(&ct);
    Ok(format!("{VERSION_PREFIX}{}", b64e(&combined)))
}

pub fn encrypt_field(vault_key: &[u8], plaintext: &str) -> Result<String, CryptoError> {
    // Matches Android encryptField: empty in -> empty out.
    if plaintext.is_empty() {
        return Ok(String::new());
    }
    let nonce = random_bytes::<NONCE_LEN>()?;
    encrypt_field_with_nonce(vault_key, plaintext, &nonce)
}

pub fn decrypt_field(vault_key: &[u8], ciphertext: &str) -> Result<String, CryptoError> {
    if ciphertext.is_empty() {
        return Ok(String::new());
    }
    let raw = ciphertext.strip_prefix(VERSION_PREFIX).unwrap_or(ciphertext);
    let combined = b64d(raw)?;
    if combined.len() <= NONCE_LEN {
        return Err(CryptoError::InvalidInput("field ciphertext too short"));
    }
    let (nonce, ct) = combined.split_at(NONCE_LEN);
    let pt = aead::decrypt(vault_key, nonce, ct)?;
    String::from_utf8(pt).map_err(|_| CryptoError::InvalidInput("plaintext not utf-8"))
}

#[cfg(test)]
mod tests;
```

### 6.7 `crypto-core/src/tests.rs` (in-crate exact-byte golden test)

```rust
//! Exact-byte golden-vector tests. These live inside the crate so they can use the
//! `pub(crate)` nonce-injecting helpers to assert deterministic *encryption* output.
//! Public-API decryption + round-trip lives in `tests/vectors.rs`.

use crate::*;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use std::path::PathBuf;

fn load_vectors() -> Option<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/vectors.json");
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn parse_params(v: &Value) -> KdfParams {
    let p = &v["params"];
    if p.is_object() {
        KdfParams {
            iterations: p["iterations"].as_u64().unwrap() as u32,
            memory_kib: p["memory_kib"].as_u64().unwrap() as u32,
            parallelism: p["parallelism"].as_u64().unwrap() as u32,
        }
    } else {
        DEFAULT_PARAMS
    }
}

fn dec(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}

fn nonce12(s: &str) -> [u8; 12] {
    dec(s).try_into().expect("nonce must be 12 bytes")
}

#[test]
fn golden_vectors_exact_bytes() {
    let Some(root) = load_vectors() else {
        eprintln!("test-vectors/vectors.json not generated — skipping. Run: cd test-vectors && node generate.mjs > vectors.json");
        return;
    };
    let vectors = root["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "no vectors found");

    for v in vectors {
        let name = v["name"].as_str().unwrap_or("<unnamed>");
        let op = v["op"].as_str().expect("op");
        let inp = &v["input"];
        let exp = &v["expected"];

        match op {
            "derive_auth_hash" => {
                let got = derive_auth_hash(
                    inp["password"].as_str().unwrap(),
                    inp["salt_str"].as_str().unwrap(),
                    &parse_params(v),
                )
                .unwrap();
                assert_eq!(got, exp["auth_hash_b64"].as_str().unwrap(), "{name}");
            }
            "derive_kek" => {
                let got = derive_kek(
                    inp["password"].as_str().unwrap(),
                    inp["salt_b64"].as_str().unwrap(),
                    &parse_params(v),
                )
                .unwrap();
                assert_eq!(STANDARD.encode(got), exp["kek_raw_b64"].as_str().unwrap(), "{name}");
            }
            "wrap_vault_key" => {
                let got = wrap_vault_key_with_nonce(
                    &dec(inp["kek_raw_b64"].as_str().unwrap()),
                    &dec(inp["vault_key_raw_b64"].as_str().unwrap()),
                    &nonce12(inp["nonce_b64"].as_str().unwrap()),
                )
                .unwrap();
                assert_eq!(got, exp["wrapped_b64"].as_str().unwrap(), "{name}");
            }
            "encrypt_entry" => {
                let got = encrypt_entry_with_nonce(
                    &dec(inp["vault_key_raw_b64"].as_str().unwrap()),
                    inp["plaintext_json"].as_str().unwrap(),
                    &nonce12(inp["nonce_b64"].as_str().unwrap()),
                )
                .unwrap();
                assert_eq!(got.encrypted_data, exp["encrypted_data"].as_str().unwrap(), "{name} data");
                assert_eq!(got.iv, exp["iv"].as_str().unwrap(), "{name} iv");
            }
            "encrypt_field" => {
                let got = encrypt_field_with_nonce(
                    &dec(inp["vault_key_raw_b64"].as_str().unwrap()),
                    inp["plaintext"].as_str().unwrap(),
                    &nonce12(inp["nonce_b64"].as_str().unwrap()),
                )
                .unwrap();
                assert_eq!(got, exp["ciphertext"].as_str().unwrap(), "{name}");
            }
            other => panic!("unknown op in vectors.json: {other}"),
        }
    }
}
```

### 6.8 `crypto-core/tests/vectors.rs` (public-API decrypt + round-trip)

```rust
//! Public-API contract tests: decryption against the golden vectors + round-trips.
//! This mirrors exactly what the wasm / UniFFI bindings expose (no nonce injection),
//! so passing here means a binding can pass too. Exact-byte encryption equality is
//! covered by the in-crate unit test (`src/tests.rs`).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use securevault_crypto_core::*;
use serde_json::Value;
use std::path::PathBuf;

fn load_vectors() -> Option<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn dec(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}

#[test]
fn decrypt_and_roundtrip_against_vectors() {
    let Some(root) = load_vectors() else {
        eprintln!("test-vectors/vectors.json not generated — skipping. Run: cd test-vectors && node generate.mjs > vectors.json");
        return;
    };

    for v in root["vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap_or("<unnamed>");
        let op = v["op"].as_str().unwrap();
        let inp = &v["input"];
        let exp = &v["expected"];

        match op {
            "wrap_vault_key" => {
                // Decrypt the golden wrapped key and confirm it yields the vault key.
                let kek = dec(inp["kek_raw_b64"].as_str().unwrap());
                let expected_vk = dec(inp["vault_key_raw_b64"].as_str().unwrap());
                let unwrapped = unwrap_vault_key(&kek, exp["wrapped_b64"].as_str().unwrap()).unwrap();
                assert_eq!(unwrapped, expected_vk, "{name} unwrap");
            }
            "encrypt_entry" => {
                let vk = dec(inp["vault_key_raw_b64"].as_str().unwrap());
                let c = EntryCiphertext {
                    encrypted_data: exp["encrypted_data"].as_str().unwrap().to_string(),
                    iv: exp["iv"].as_str().unwrap().to_string(),
                };
                assert_eq!(decrypt_entry(&vk, &c).unwrap(), inp["plaintext_json"].as_str().unwrap(), "{name}");
            }
            "encrypt_field" => {
                let vk = dec(inp["vault_key_raw_b64"].as_str().unwrap());
                let got = decrypt_field(&vk, exp["ciphertext"].as_str().unwrap()).unwrap();
                assert_eq!(got, inp["plaintext"].as_str().unwrap(), "{name}");
            }
            _ => {} // derive_* covered by exact-byte unit test
        }
    }
}

#[test]
fn roundtrips_without_vectors() {
    // Always-on smoke test, independent of vectors.json.
    let vk = generate_vault_key().unwrap();

    let entry = r#"{"a":1,"b":"x"}"#;
    let c = encrypt_entry(&vk, entry).unwrap();
    assert!(c.encrypted_data.starts_with("v1:"));
    assert_eq!(decrypt_entry(&vk, &c).unwrap(), entry);

    let field = encrypt_field(&vk, "secret").unwrap();
    assert_eq!(decrypt_field(&vk, &field).unwrap(), "secret");
    assert_eq!(encrypt_field(&vk, "").unwrap(), "");
    assert_eq!(decrypt_field(&vk, "").unwrap(), "");

    let salt = generate_salt().unwrap();
    let kek = derive_kek("pw", &salt, &DEFAULT_PARAMS).unwrap();
    let wrapped = wrap_vault_key(&kek, &vk).unwrap();
    assert_eq!(unwrap_vault_key(&kek, &wrapped).unwrap(), vk);

    // Determinism + tamper detection.
    let h1 = derive_auth_hash("pw", "saltstring", &DEFAULT_PARAMS).unwrap();
    let h2 = derive_auth_hash("pw", "saltstring", &DEFAULT_PARAMS).unwrap();
    assert_eq!(h1, h2);
    assert!(unwrap_vault_key(&kek, &STANDARD.encode([0u8; 60])).is_err());
}

#[test]
fn rejects_downgraded_params() {
    let weak = KdfParams { iterations: 1, memory_kib: 8, parallelism: 1 };
    assert!(validate_params(&weak).is_err());
    assert!(validate_params(&DEFAULT_PARAMS).is_ok());
}
```

### 6.9 `crypto-core/.gitignore`

```gitignore
/target
Cargo.lock
```

> ⚠️ **Reconsider committing `Cargo.lock`.** The whole point is one identical artifact
> across platforms; pinning the same dependency versions everywhere argues for committing
> the lockfile. Currently ignored (library convention).

### 6.10 `crypto-core/DESIGN.md`

A separate design doc already exists at `crypto-core/DESIGN.md` (the full spec, repo/CI
layout, bindings plan, rollout, and risks). It is not duplicated here — read it directly.
Its key content is summarized in §4, §5, and §10 of this document.

---

## 7. Golden test vectors — full source

Location: `test-vectors/`. These freeze the v2 format so every implementation (Rust core,
web wasm, Android, iOS) can be verified byte-for-byte.

### 7.1 `test-vectors/generate.mjs`

```js
// Deterministic golden-vector generator for SecureVault crypto-core.
//
// Reproduces the EXACT current v2 client format (web `web/src/crypto/*`, Android
// `AndroidEntryEncryptor.kt`). All salts / keys / nonces are FIXED constants so the
// output is byte-for-byte reproducible — these vectors become the cross-platform
// contract (Rust core, web wasm, Android, iOS must all match).
//
// Usage:
//   cd test-vectors && npm i hash-wasm && node generate.mjs > vectors.json
//
// Requires Node >= 20 (global Web Crypto). `hash-wasm` MUST be the same major version
// the web app uses (see web/package.json) so Argon2id output matches the shipped app.

// hash-wasm is only needed for the KDF (Argon2id) vectors. The envelope/AES-GCM
// vectors use Node's native WebCrypto (the same primitive the web app uses), so they
// generate even when the npm registry is unreachable. KDF vectors are emitted only
// when hash-wasm is installed.
let argon2id = null
try {
  ;({ argon2id } = await import('hash-wasm'))
} catch {
  console.error('[warn] hash-wasm not installed — emitting envelope/AES vectors only (no KDF vectors).')
}

const subtle = globalThis.crypto.subtle

// ---- helpers (match web/src/crypto/util.ts: standard base64, NOT url-safe) ----
const b64 = (bytes) => Buffer.from(bytes).toString('base64')
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'))
const utf8 = (s) => new TextEncoder().encode(s)

async function aesGcmEncrypt(keyBytes, iv, plaintextBytes) {
  const key = await subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt'])
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plaintextBytes)
  return new Uint8Array(ct) // ct || tag  (tag appended; same as JCA / RustCrypto)
}

async function argon(password, saltBytes, p) {
  return argon2id({
    password,
    salt: saltBytes,
    parallelism: p.parallelism,
    iterations: p.iterations,
    memorySize: p.memory_kib,
    hashLength: 32,
    outputType: 'binary',
  })
}

// ---- FIXED test inputs (never randomize — that's the whole point) ----
const PARAMS = { iterations: 4, memory_kib: 65536, parallelism: 4 }
const PASSWORD = 'correct horse battery staple'
const AUTH_SALT = 'auth-salt-fixed-string'              // authHash: used as UTF-8 STRING bytes
const ENC_SALT_B64 = b64(utf8('0123456789abcdef'))      // KEK: base64-decoded to 16 raw bytes
const VAULT_KEY = new Uint8Array(32).map((_, i) => i)   // 00,01,...,1f
const NONCE = new Uint8Array(12).map((_, i) => 0xa0 + i)
const ENTRY_JSON = '{"password":"hunter2","title":"Example","url":"https://example.com","username":"alice"}'

const cases = []

// KDF vectors require hash-wasm. The KEK is also needed to wrap the vault key
// (envelope A) the *web* way, so when hash-wasm is absent we fall back to a fixed
// 32-byte KEK for envelope A — that still validates the AES-GCM wrap layout.
let kek
if (argon2id) {
  // auth_hash — salt as UTF-8 string bytes (web derivePasswordHash)
  cases.push({
    name: 'auth_hash/default-params',
    op: 'derive_auth_hash',
    params: PARAMS,
    input: { password: PASSWORD, salt_str: AUTH_SALT },
    expected: { auth_hash_b64: b64(await argon(PASSWORD, utf8(AUTH_SALT), PARAMS)) },
  })

  // kek — salt base64-decoded to raw bytes (web deriveKek)
  kek = await argon(PASSWORD, unb64(ENC_SALT_B64), PARAMS)
  cases.push({
    name: 'kek/default-params',
    op: 'derive_kek',
    params: PARAMS,
    input: { password: PASSWORD, salt_b64: ENC_SALT_B64 },
    expected: { kek_raw_b64: b64(kek) },
  })
} else {
  kek = new Uint8Array(32).map((_, i) => 0x40 + i) // fixed stand-in KEK for envelope A
}

// envelope A — wrapped key: base64( nonce[12] || ct||tag )
const wrappedCt = await aesGcmEncrypt(kek, NONCE, VAULT_KEY)
const wrappedCombined = new Uint8Array(12 + wrappedCt.length)
wrappedCombined.set(NONCE, 0)
wrappedCombined.set(wrappedCt, 12)
cases.push({
  name: 'envelope_a/wrap_vault_key',
  op: 'wrap_vault_key',
  input: { kek_raw_b64: b64(kek), vault_key_raw_b64: b64(VAULT_KEY), nonce_b64: b64(NONCE) },
  expected: { wrapped_b64: b64(wrappedCombined) },
})

// envelope B — entry: encryptedData = "v1:"+b64(ct||tag), separate iv = b64(nonce)
const entryCt = await aesGcmEncrypt(VAULT_KEY, NONCE, utf8(ENTRY_JSON))
cases.push({
  name: 'envelope_b/encrypt_entry',
  op: 'encrypt_entry',
  input: { vault_key_raw_b64: b64(VAULT_KEY), plaintext_json: ENTRY_JSON, nonce_b64: b64(NONCE) },
  expected: { encrypted_data: 'v1:' + b64(entryCt), iv: b64(NONCE) },
})

// envelope C — local field: "v1:"+b64(nonce||ct||tag)  (Android encryptField)
const fieldPt = 'hunter2'
const fieldCt = await aesGcmEncrypt(VAULT_KEY, NONCE, utf8(fieldPt))
const fieldCombined = new Uint8Array(12 + fieldCt.length)
fieldCombined.set(NONCE, 0)
fieldCombined.set(fieldCt, 12)
cases.push({
  name: 'envelope_c/encrypt_field',
  op: 'encrypt_field',
  input: { vault_key_raw_b64: b64(VAULT_KEY), plaintext: fieldPt, nonce_b64: b64(NONCE) },
  expected: { ciphertext: 'v1:' + b64(fieldCombined) },
})

process.stdout.write(JSON.stringify({
  _description: 'SecureVault crypto-core golden vectors (v2 format). Generated by generate.mjs — do not hand-edit.',
  encryption_version: 2,
  base64: 'standard (RFC 4648, not url-safe), no padding stripping',
  vectors: cases,
}, null, 2) + '\n')
```

### 7.2 `test-vectors/README.md`

A separate README at `test-vectors/README.md` documents how to generate/consume the vectors
and a table of what each vector pins. Not duplicated here.

### 7.3 `test-vectors/vectors.json` (currently PARTIAL — envelope-only)

Generated **without** `hash-wasm` (npm registry was blocked), so it contains only the three
envelope vectors. Regenerate with `hash-wasm` to add `auth_hash` + `kek`. Current content:

```json
{
  "_description": "SecureVault crypto-core golden vectors (v2 format). Generated by generate.mjs — do not hand-edit.",
  "encryption_version": 2,
  "base64": "standard (RFC 4648, not url-safe), no padding stripping",
  "vectors": [
    {
      "name": "envelope_a/wrap_vault_key",
      "op": "wrap_vault_key",
      "input": {
        "kek_raw_b64": "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=",
        "vault_key_raw_b64": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "nonce_b64": "oKGio6Slpqeoqaqr"
      },
      "expected": {
        "wrapped_b64": "oKGio6Slpqeoqaqr144EPObumipxZkv1hbE++f8G59T4epM6+sX0gfXfYOfVgsU2iTHoyb7JwEPGP1Ud"
      }
    },
    {
      "name": "envelope_b/encrypt_entry",
      "op": "encrypt_entry",
      "input": {
        "vault_key_raw_b64": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "plaintext_json": "{\"password\":\"hunter2\",\"title\":\"Example\",\"url\":\"https://example.com\",\"username\":\"alice\"}",
        "nonce_b64": "oKGio6Slpqeoqaqr"
      },
      "expected": {
        "encrypted_data": "v1:nToMTDa4ddAQAaXpJRK1sATJKyKwm2AY9XpK412RV0SqFyqPw0dxEX3pdqQrQKGRM282O1j/NRs5P2YuyBWr09vRp0MS0JeFhoyeders9pisZ8LHoOPk2ip89WpgBc3FF2Wrs3TNww==",
        "iv": "oKGio6Slpqeoqaqr"
      }
    },
    {
      "name": "envelope_c/encrypt_field",
      "op": "encrypt_field",
      "input": {
        "vault_key_raw_b64": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "plaintext": "hunter2",
        "nonce_b64": "oKGio6Slpqeoqaqr"
      },
      "expected": {
        "ciphertext": "v1:oKGio6Slpqeoqaqrjm0SWSC5MCfL5aobdPsWtGz5Z/PKjqM="
      }
    }
  ]
}
```

> **Recommendation:** don't commit `vectors.json` until it includes the KDF vectors, so the
> committed contract isn't misleadingly incomplete.

---

## 8. Verification results

All run in this session with the Rust toolchain (`cargo 1.96.0`) and Node 26.

| Check | Result |
|-------|--------|
| `cargo test` (crypto-core) | ✅ **all pass** — `golden_vectors_exact_bytes` (1), `tests/vectors.rs` (3: decrypt+roundtrip, smoke, downgrade-reject) |
| `cargo clippy --all-targets` | ✅ **no warnings/errors** |
| Compile against real crate APIs (`argon2 0.5`, `aes-gcm 0.10`, `base64 0.22`) | ✅ |
| Envelope parity: Rust `aes-gcm`/`base64` vs **Node WebCrypto** (3 envelope vectors) | ✅ **byte-for-byte** |
| Negative control (tamper one vector → test must fail) | ✅ failed as expected with a clear diff |
| Backend Java changes | ⚠️ **not compiled** (no Maven/JRE in env) |
| Web TS changes | ⚠️ **not type-checked** (Node added later; changes mirror existing patterns) |
| **KDF (Argon2id) parity** vs hash-wasm | ❌ **blocked** — `registry.npmjs.org` returns 503 (env allows only Meta domains); no `argon2` CLI / `argon2-cffi` / cached copy available |

**What "envelope parity proven" means:** two independent AES-GCM stacks (RustCrypto vs
WebCrypto) agree exactly on all three layouts, the separate-IV quirk, the `v1:` prefix,
base64 alphabet/padding, and GCM tag-append order. The negative control proves the test
genuinely asserts (it is not silently skipping).

**What KDF parity would prove (still open):** that hash-wasm's Argon2id with these params
produces the same 32 bytes as RustCrypto's. Structurally everything is pinned (Argon2id,
version 0x13, m/t/p order, salt asymmetry, 32-byte output) and Argon2 is deterministic per
spec, so conformant implementations must agree — but it isn't a green test yet.

To close it on a networked machine:
```bash
cd test-vectors && npm i hash-wasm && node generate.mjs > vectors.json
cd ../crypto-core && cargo test    # now also asserts auth_hash + kek byte-for-byte
```

---

## 9. What's done / what's pending

### ✅ Done
- Full security review across backend, web/extension, and mobile (§2).
- **`upgrade-kdf` Critical fix** — `@RequireSudo` + KDF bounds (backend) and web client sudo
  wiring (§3). *(Not compiled/type-checked in this env.)*
- Architecture decision + design doc for a single Rust crypto core (§4, `crypto-core/DESIGN.md`).
- The crypto v2 format reverse-engineered and documented exactly (§5).
- **`crypto-core` crate written, compiling, clippy-clean, all tests passing** (§6, §8).
- Golden-vector harness; **envelope/format parity proven byte-for-byte vs WebCrypto** (§7, §8).

### ⏳ Pending / blocked
- **KDF parity** vs hash-wasm/argon2kt — blocked here (registry); the harness is ready.
- **Confirm Android authHash salt encoding** matches web (UTF-8 string).
- **Unify entry-plaintext JSON** (canonical serialization in the core).
- **No bindings yet** — `wasm-bindgen` (web), UniFFI (mobile), build scripts, CI.
- **No integration** — call sites in web/Android/iOS not replaced; old code not deleted.
- Decide whether `crypto-core/Cargo.lock` should be committed.
- Decide whether `upgrade-kdf` should also revoke refresh tokens.

### ❗ Security findings still OPEN (everything except C1/C2)
All High/Medium/Low items in §2 remain unaddressed, notably: extension content-script scope
& refresh-token storage (W-C1/W-C2), the entire iOS crypto/storage layer (M-C1/M-C2/M-C3),
CORS+localhost (H1), XFF trust (H2), sudo-token-via-query (H3).

---

## 10. Complete replacement plan (all steps)

Sequenced so each phase is verifiable and existing vaults never break.

### Phase 0 — Finalize & freeze the core contract
- [ ] Confirm Android's authHash salt encoding vs `CryptoEngine.android.kt`.
- [ ] Unify entry-plaintext JSON (canonical, stable key order) into the core or a pinned schema.
- [ ] Lock `DEFAULT_PARAMS` / `MIN_PARAMS` and the `validate_params` call sites.
- [ ] Commit `Cargo.lock` so all platforms build identical dependency versions.
- [ ] Tag a core version (e.g. `1.0.0`); all platforms pin it.

### Phase 1 — Prove parity (hard gate)
- [ ] Generate full `vectors.json` (KDF + envelopes) with `hash-wasm`.
- [ ] `cargo test` green on **all** vectors (KDF byte-for-byte).
- [ ] Android oracle: generate vectors from `argon2kt` in an instrumented test; confirm match.
- [ ] **Do not proceed** until KDF parity is green on web AND Android oracles.

### Phase 2 — Build & binding infrastructure
- [ ] Web: `wasm-bindgen` exports + `wasm-pack build --target web`; typed TS module; wasm memory headroom for 64 MB Argon2.
- [ ] Mobile: UniFFI interface → Kotlin + Swift.
- [ ] Android: `cargo-ndk` → `.so` for `arm64-v8a`, `armeabi-v7a`, `x86_64`.
- [ ] iOS: per-target static libs → XCFramework.
- [ ] CI: build all artifacts (iOS needs macOS runner) + run vectors **through the generated bindings**.

### Phase 3 — Web integration (lowest risk; format parity already proven)
- [ ] Wrap wasm behind existing interfaces in `web/src/crypto/{argon2,vaultKey,entries,util}.ts`.
- [ ] Ship behind a feature flag; shadow-diff old TS vs new wasm.
- [ ] Verify register → login → unlock → add/edit/decrypt → change-password → `upgrade-kdf` against a real backend on an **existing** account.
- [ ] Run web tests; remove flag; delete TS crypto impls (keep thin wrappers).

### Phase 4 — Android integration
- [ ] Replace Argon2/AES bodies in `AndroidEntryEncryptor.kt` and `CryptoEngine.android.kt` actual with UniFFI calls; move orchestration to `commonMain`.
- [ ] Run Argon2 off the main thread.
- [ ] Verify against an **existing real Android vault** (unlock + decrypt entries written by web).
- [ ] Run instrumented tests + vectors via binding; delete old Kotlin crypto.

### Phase 5 — iOS integration (the fix)
- [ ] Replace `CryptoEngine.ios.kt` + `IosEntryEncryptor.kt` with the UniFFI binding (Argon2id + real GCM + canonical JSON).
- [ ] Verify iOS unlocks/decrypts vaults written by web/Android.
- [ ] Implement Keychain-backed `SessionManager` for iOS (separate but required for a usable app).

### Phase 6 — Browser extension
- [ ] Point `web/extension/src/lib/{argon2,vaultKey,entries}.ts` at the same wasm module; delete the duplicate crypto.

### Phase 7 — Rollout & production verification
- [ ] Staged rollout per platform (web → Android → iOS), each behind a flag with a rollback path.
- [ ] Monitor decrypt/unlock-failure rates; a spike = parity miss → roll back.
- [ ] Confirm `upgrade-kdf` / `change-password` still re-wrap correctly through the new core.

### Phase 8 — Cleanup & guardrails
- [ ] Delete duplicated client constants (`DEFAULT_KDF_*` in web, extension, `CryptoEngine.kt`); source from the core. Leave server `EncryptionConstants.java`.
- [ ] Keep server crypto untouched (zero-knowledge boundary).
- [ ] Make the vector suite a required CI check on every platform.
- [ ] Document the version-bump process (raise core version → rebuild all artifacts → re-run vectors → ship together).

### Two hard gates
1. **Phase 1 (KDF parity)** — never integrate before green on web + Android oracles.
2. **Per-platform "reads an existing vault"** — the real proof of no silent data migration.

---

## 11. File inventory & commands

### Files created this session
```
crypto-core/Cargo.toml
crypto-core/.gitignore
crypto-core/DESIGN.md
crypto-core/src/lib.rs
crypto-core/src/error.rs
crypto-core/src/params.rs
crypto-core/src/kdf.rs
crypto-core/src/aead.rs
crypto-core/src/tests.rs
crypto-core/tests/vectors.rs
test-vectors/generate.mjs
test-vectors/README.md
test-vectors/vectors.json        (partial — envelope-only; regenerate with hash-wasm)
SECURITY_AND_CRYPTO_CORE.md      (this document)
```

### Files modified this session (the `upgrade-kdf` fix)
```
src/main/java/com/securevault/controller/AuthController.java   (+ @RequireSudo on upgradeKdf)
src/main/java/com/securevault/dto/UpgradeKdfRequest.java       (+ KDF bounds, @Size)
web/src/api/auth.ts                                            (upgradeKdf accepts sudoToken)
web/src/context/VaultContext.tsx                               (requestSudo before upgradeKdf)
```

### Commands
```bash
# Rust core: build, test, lint
cd crypto-core && cargo test && cargo clippy --all-targets

# Generate full golden vectors (needs network for hash-wasm)
cd test-vectors && npm i hash-wasm && node generate.mjs > vectors.json

# Backend (once a JDK/Maven is available)
mvn -o compile        # or ./mvnw compile

# Web (type-check)
cd web && npx tsc -p tsconfig.app.json --noEmit
```

---

## 12. Evolving the cryptography (how to update crypto safely)

> Captures the discussion on "how should I approach updating the cryptography?" The
> governing constraint: **this is zero-knowledge, so the server can never re-encrypt anyone's
> data — only the client, holding the password, can.** Every migration is therefore
> client-side and lazy.

### 12.1 Step 1 — Classify the change (this decides the effort)

| Type | Examples | Format/byte-layout change? | Effort |
|------|----------|----------------------------|--------|
| **A. Parameter tuning** | Raise Argon2 memory/iterations; raise `MIN_PARAMS` | No — same algorithm & layout | Low |
| **B. Format / algorithm change** | AES-GCM → XChaCha20-Poly1305; add AAD; change envelope layout; change KDF | Yes | High |
| **C. Add data to the envelope** | New header field, key-id, AAD | Yes (new version) | Medium |

The deciding question: **does the ciphertext byte layout or the algorithm change?**
No → Type A (cheap; the machinery already exists). Yes → Type B/C (versioning + dual-read).

### 12.2 Step 2 — The rules that ALWAYS apply

1. **Version every ciphertext.** Already partly in place: `encryptionVersion` per account
   (`CURRENT_ENCRYPTION_VERSION = 2`) and the `"v1:"` prefix on entry/field envelopes. A real
   format change must introduce a **new discriminator** (`"v2:"` prefix or bumped
   `encryptionVersion`) so `decrypt` can dispatch to the correct scheme.
2. **Never drop the ability to read old versions.** Decryption stays multi-version *forever*.
   You add a new branch; you don't replace the old one. Old golden vectors stay in the suite
   permanently.
3. **Migration is lazy and client-side.** You can only re-wrap/re-encrypt when the user
   supplies the password (on unlock/login) — exactly how `upgrade-kdf` works today.
4. **All clients must READ the new version before ANY client WRITES it.** Otherwise a vault
   re-encrypted by an updated web client won't open on an old mobile client. This forces a
   two-phase rollout (deploy readers first, enable writers later).
5. **Cross-client byte-for-byte parity**, enforced by golden vectors (the reason for the
   Rust core).

### 12.3 Step 3 — The procedure per type

**Type A — parameter tuning (e.g. bump Argon2 memory):**
1. Raise the default (`DEFAULT_PARAMS` in the core / `DEFAULT_KDF_*` clients /
   `EncryptionConstants` server).
2. Existing accounts keep old params; on next unlock the **`upgrade-kdf` lazy migration**
   re-derives KEK + auth hash with the new params and re-wraps.
3. Optionally raise `MIN_PARAMS` (the downgrade floor) — but **only to a value ≤ the oldest
   legitimately-issued params**, or you'll lock out vaults you can no longer derive. Keep
   `validate_params` separate from `derive_*` (derivation must reproduce ANY params).
4. Add a golden vector at the new params; keep the old one.
   *No format change, no version bump, no dual-read.*

**Type B/C — format or algorithm change:**
1. Design the new scheme in the Rust core behind a new version constant (`v3`) with its own
   envelope discriminator. Leave `v2` decrypt untouched.
2. Add golden vectors for the new version (keep all old ones).
3. **Dual-read:** `decrypt` dispatches on prefix/version → v2 or v3. `encrypt` is gated by a
   flag so you control *when* it starts writing v3.
4. **Rollout phase 1 — readers everywhere:** ship the new core (v3 *read* support) to web,
   Android, iOS. Do NOT enable v3 writing. Wait until all platforms are updated in the field.
5. **Rollout phase 2 — enable writers:** flip the write flag. Lazily on unlock, clients
   re-encrypt v2 → v3 (same pattern as `upgrade-kdf`) and bump the account's
   `encryptionVersion`.
6. **Long tail:** v2 data lingers for users who haven't logged in — fine, dual-read handles
   it. Drop v2 *write* (done in phase 2); **never** drop v2 *read*.

### 12.4 Where the Rust core makes this safe
With one core: a crypto change is **one branch in one codebase** (not three hand-synced
impls); **golden vectors** pin every version on every platform (mismatch fails CI instead of
locking users out); the version/prefix dispatch lives in one auditable place. Until the core
is adopted, a Type B change means making the identical change correctly in TS + Kotlin +
Swift and proving they agree — the exact drift problem that left iOS broken.

### 12.5 Safety gates (don't skip)
- ✅ New **and all old** versions pass golden vectors on **every** platform.
- ✅ "Reads an existing (old-version) vault" verified per platform — proves no data loss.
- ✅ Writers enabled only **after** all clients can read the new version.
- ✅ Feature-flagged rollout with a rollback path; monitor decrypt/unlock-failure rates.
- ✅ `MIN_PARAMS`/floor never exceeds the weakest params you must still derive.

**TL;DR:** Ask *"does the byte layout/algorithm change?"* If no → bump params, let the lazy
`upgrade-kdf` mechanism migrate on unlock. If yes → new `encryptionVersion`, keep old decrypt
forever, ship **read** to all clients first, then enable **write** (lazy re-encryption),
pinned by golden vectors in the single Rust core.

---

## 13. Golden vectors explained

> Captures the "what are golden vectors?" discussion.

**Definition.** A golden vector (a.k.a. test vector / known-answer test / KAT) is a **fixed
input paired with its known-correct output**, used to verify an implementation produces
exactly the right bytes. For crypto: pick a *fixed* password, salt, key, and nonce (never
random), run them through a trusted implementation once, and **record the exact output**. Any
other implementation must reproduce that output byte-for-byte or it is wrong. The name: the
recorded output is the "gold standard" source of truth.

**Why they're essential.** Crypto has a nasty property: **wrong code often still "works."**
If nonce handling or an Argon2 parameter order is subtly wrong, encrypt/decrypt can still
round-trip *on the same machine* — it just produces *different bytes than everyone else*. You
won't notice until a vault written on web fails to open on iOS. Round-trip tests can't catch
this (both halves share the bug); golden vectors can, because they compare against an
**external fixed expected value**.

**Concrete example (this project, `test-vectors/vectors.json`):**
```json
{
  "op": "encrypt_entry",
  "input": {
    "vault_key_raw_b64": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    "plaintext_json": "{\"password\":\"hunter2\",...}",
    "nonce_b64": "oKGio6Slpqeoqaqr"
  },
  "expected": {
    "encrypted_data": "v1:nToMTDa4ddAQAaXpJRK1sATJKyKwm2AY9XpK412RV0Sq...",
    "iv": "oKGio6Slpqeoqaqr"
  }
}
```
- **input** = fixed vault key + plaintext + nonce (nonce pinned so output is reproducible; in
  production the nonce is always random).
- **expected** = the exact ciphertext **Node's WebCrypto** (what the web app uses) produced.

The Rust core runs the same input and asserts it gets the same `expected` bytes. When we ran
`cargo test` it matched → the Rust impl is byte-compatible with the web impl. The **negative
control** (tampering one byte of `expected`) made the test *fail* — proving the test really
checks rather than silently passing.

**How they're used here.** `vectors.json` is the **cross-platform contract**: web, Android,
iOS, and the Rust core all run the same vectors in CI. If any platform's output differs from
the golden value, that platform can't read vaults written by the others — and CI fails
*before* shipping, instead of users getting locked out in production. Retaining old vectors
forever is what makes evolving the crypto (§12) safe.

**Real-world precedent:** published standards ship these too — RFC 9106 (Argon2) and NIST's
AES test vectors include fixed input→output pairs precisely so every implementation can prove
conformance.

---

## 14. Threat model — how safe is the vault from an attacker

> Captures the "how safe is this from an attacker?" assessment. Verdict in one line:
> **strong design, not yet production-hardened — and safety depends heavily on platform and
> master-password strength.**

### 14.1 Threat-by-threat

**1. Server / database breach — the defining test → Strong (web/Android).** A stolen DB gives
only `serverSideHash(authHash)`, the **encrypted** `wrappedVaultKey`, salts, and KDF params.
To get passwords the attacker must brute-force the **master password** offline through
Argon2id (64 MB, t=4) then unwrap. Strong password → effectively uncrackable; weak password →
still at risk (`t=4` is on the low side). The KDF-downgrade bug that could have *weakened*
this wall was **fixed this session**.

**2. Network attacker (MITM) → Moderate, with real gaps.** TLS is the main defense, but: no
**cert pinning** on mobile, no **client-side KDF floor** (a MITM tampering the prelogin
response could push `iterations=1`), the **extension autofills on plain `http://`**, and iOS
ships an `http://localhost` base URL.

**3. Stolen access token / session → Limited blast radius now.** Tokens are short-lived
(~1h); sensitive actions require sudo re-auth, and the one that didn't (`upgrade-kdf`) was
fixed. IDOR/ownership checks are correct (token for A can't touch B's data).

**4. Online password guessing → Mostly mitigated, with bypasses.** Rate limiting + lockout
exist, but IP limits can be **bypassed via `X-Forwarded-For` spoofing** (behind a trusted
proxy that doesn't strip it), and the TOTP verify path has a wider brute-force surface.

**5. Device access (lost/stolen, malware) → Platform-dependent.**
- Web: vault key in memory only, 5-min auto-lock (no lock on blur/background). Reasonable.
- Android: decent (FLAG_SECURE, no backup) but local DB key not auth-gated (recoverable on a
  **rooted** device); titles/usernames cached **unencrypted**.
- iOS: ❌ no secure storage, unauthenticated crypto, no screenshot protection.
- Extension: weak — **refresh token in plaintext on disk**, no auto-lock.

**6. Malicious website / browser attacker → Weak (extension users).** The content script runs
on **every site** with **no sender/origin validation** → a hostile page could solicit
decrypted entries or trigger autofill in the wrong context. The web app itself has no XSS
sinks (good).

**7. Application-logic attacks → Solid.** No IDOR, no 2FA bypass found, `upgrade-kdf` takeover
fixed.

### 14.2 Who's actually safe?

| You are… | strong master password | weak master password |
|----------|------------------------|----------------------|
| Web user + 2FA | 🟢 Safe, incl. vs server breach | 🟡 Mostly — weak password is the risk |
| Android user | 🟢 Good (local risks need root) | 🟡 Moderate |
| Browser-extension user | 🟡 Browser-attack + on-disk-token risks | 🔴 Multiple weak points |
| iOS user | 🔴 **Not safe** (broken crypto & storage) | 🔴 Not safe |

### 14.3 The fixes that move the needle most
1. **Strong, unique master password + 2FA** — dominates real-world safety.
2. **Fix iOS** (authenticated crypto + Keychain).
3. **Lock down the extension** (no `http://` autofill, restrict origins, token off disk).
4. **Client-side KDF floor + mobile cert pinning** (closes MITM-downgrade).
5. **Fix `X-Forwarded-For` trust** (restores brute-force protection).

**Bottom line:** a well-built, genuinely zero-knowledge architecture; as shipped today it's
safe for a **web/Android user with a strong master password and 2FA**, **not yet safe for
iOS**, with **meaningful gaps for extension users and against active network attackers**.

---

## 15. Making it unbreakable: weak password + full server/DB breach

> Captures the discussion on surviving the worst case: **weak master password AND attacker
> has full server + database access** (ignoring iOS).

### 15.1 The hard truth: the KDF alone cannot do it
A weak password has **low entropy**. Argon2id only makes each guess *expensive* — it
multiplies cost, it doesn't add entropy. Against an attacker with the full DB and unlimited
offline compute, low entropy always falls eventually. So this goal is **impossible** while the
*only* secret protecting the vault is derived from the password and present (wrapped) in the
DB. You must add **a secret that is never in the database and never on the server.**

### 15.2 The direct answer — a client-side "Secret Key" (1Password model)
At signup the client generates a **high-entropy random secret** (128–256 bits) that is
generated **on-device**, **never sent to the server**, and stored on the user's devices
(shown once for backup). The KEK is derived from **both** password and Secret Key:
```
KEK = HKDF( Argon2id(password, salt, params)  ||/XOR  SecretKey )
```
In this repo that's a change to `deriveKek` (`web/src/crypto/argon2.ts` / Rust `derive_kek`):
fold the Secret Key into the Argon2 output before it becomes the AES-GCM key that unwraps
`wrappedVaultKey`.

**Why it works:** the attacker now needs `password × SecretKey`. Even with `password123` and
the entire database, they're missing 128+ bits of true random entropy **that was never on the
server**. Offline brute force is infeasible — there's nothing to brute-force toward.

**The cost:** usability. A new device needs the Secret Key (via backup/QR); recovery requires
it. That trade-off *is* the security. (See §16 for storage UX.)

### 15.3 Reinforcing layer — rate-limited HSM (server pepper / OPRF)
Add a secret the server *uses* but never stores in the DB, ideally inside an **HSM/KMS that
performs the operation without exporting the key**:
- **Minimum:** a secret **pepper** mixed into `serverSideHash` (today PBKDF2 only). Defeats
  **DB-only** theft (SQLi, stolen backup) where the app secrets/HSM aren't taken.
- **Strong:** an **OPRF** in the KEK path. The client blinds the password, the server applies
  its HSM-held secret, returns the result; the client derives the KEK from it. Every guess
  requires the HSM. If the HSM rate-limits, even **full server RCE** turns an offline,
  unlimited attack into an online, throttled one — survivable behind lockout.

Key distinction: a pepper in a **config file** dies with full server compromise; a secret in
a **true HSM that only evaluates and never releases the key** survives it (usable as a live,
rate-limited oracle, not extractable for offline use).

### 15.4 Reinforcing layer — hardware factor in the key path (WebAuthn-PRF)
Bind the KEK to a **hardware authenticator** via WebAuthn's **PRF / `hmac-secret`** extension:
```
KEK = HKDF( Argon2id(password) || SecretKey || WebAuthnPRF(authenticator) )
```
The vault then cannot be opened without the **physical device**, whose secret never touches
the server — the same "entropy the server never has" property, rooted in hardware, and it also
resists theft of the Secret Key backup.

### 15.5 The strongest practical combination
```
password ──Argon2id(strong params)──┐
device Secret Key (never on server) ─┤─ HKDF ─▶ KEK ─▶ unwrap wrappedVaultKey ─▶ vault key
optional: WebAuthn-PRF / server OPRF ┘            (DB only stores the wrapped key + salts)
```
- **Baseline (still do):** raise Argon2id from `t=4` toward higher time/memory.
- **#1 Secret Key** → the thing that actually answers the question.
- **#2 HSM pepper/OPRF** → defense-in-depth + rate-limits full-compromise.
- **#3 WebAuthn-PRF** → hardware-rooted, optional per user.

### 15.6 Fitting it into this codebase
- **Where:** `deriveKek` / `derive_kek` gains a Secret-Key input; registration generates +
  displays it; `serverSideHash` gains the HSM pepper/OPRF. The server stores **nothing new
  that's crackable**.
- **Migration:** bump `encryptionVersion` (v3), ship **read** support everywhere, then
  **lazily re-wrap** on unlock (the `upgrade-kdf` pattern) so existing vaults gain the Secret
  Key without a forced reset.
- **Golden vectors:** add v3 vectors; keep v2 forever.

### 15.7 The honest boundary of "unbreakable"
Achievable: **full server + DB compromise + weak password → vault stays safe.** ✅
Still NOT covered (no design can):
- Compromise of the **user's own device** (where the Secret Key + decrypted vault live).
- **Phishing** capturing password *and* Secret Key together.
- A backdoored client binary.

Honest claim you can make: *"Even if our entire server and database are stolen, your vault
cannot be decrypted — regardless of how weak your master password is — because a high-entropy
secret we never possess is required to open it."* That's the bar 1Password meets.

---

## 16. Storing the Secret Key (end-user UX)

> Captures the "how does the end user store the Secret Key?" discussion. The crux of the
> Secret Key model — get this wrong and it's either insecure or unusable.

**Reframe:** the user almost never types or manually stores it. A 128-bit key can't be
memorized, so **devices hold it**; the human only handles it at enrollment and recovery.

### 16.1 The three touchpoints
1. **First device (signup):** the client generates the Secret Key and saves it into that
   device's **secure storage** (Keychain / Keystore / `EncryptedSharedPreferences` / web
   secure storage). The device then opens the vault with just the master password; the Secret
   Key is supplied silently. The user is shown it once with a prompt to **back it up**.
2. **Adding another device:** don't make the user retype 128 bits. The normal UX is
   **device-to-device transfer** — an existing device shows a **QR code** (Secret Key +
   account info) the new device scans (1Password's "scan to set up"); or the user enters it
   from their backup. The new device then stores it in *its* secure storage too. N devices
   each independently hold it; none got it from the server.
3. **Disaster recovery (all devices lost):** the only case requiring a user-held **backup** —
   the **Emergency Kit** (a PDF/printout with the Secret Key, *not* the password). Without it
   *and* without a logged-in device, the account is unrecoverable — which is the point (the
   server never had it).

### 16.2 Where to keep the backup — and the one rule
- **Print it** and store with important documents / a home safe (recommended).
- Save the PDF to secure storage that is **NOT the same place as the master password**.
- Store in a second password manager / hardware backup.

**Non-negotiable rule:** the Secret Key and master password must be kept **separately** — the
whole benefit is that they're two independent factors from two different places. If the user
keeps both together, a breach of that one place recombines them and you're back to "weak
password = cracked." The UI must warn against this.

### 16.3 Never sync it through your server
The Secret Key must **never** travel through or rest on the backend (that would put it exactly
where a breaching attacker is). Transfer is device-to-device (QR/local) or via the user's own
backup.

### 16.4 The friendlier alternative — let hardware be the storage
If safeguarding a secret string feels too fragile (it is the model's main weakness), use a
**passkey / WebAuthn-PRF** as the second factor instead. Then "how do I store it?" becomes
**"you don't — your authenticator does."** The high-entropy secret lives in the device's
secure enclave or a YubiKey; the user just taps. Passkeys can sync across the user's own
devices (iCloud Keychain / Google Password Manager), solving multi-device enrollment.
Trade-off: need backup authenticators + reliance on the passkey ecosystem.

### 16.5 Recommended hybrid
Device-held secret auto-stored in each device's secure storage + **QR enrollment** for new
devices + a printed **Emergency Kit** cold-backup (with the "keep separate" warning) +
optional **passkey** for users who'd rather tap hardware than guard a string.

### 16.6 The honest cost
You're trading **recoverability for security**. With a server-independent secret: lose every
device *and* the backup → **permanently locked out; the provider cannot reset it.** That's the
property that makes full server+DB compromise survivable. So the UX must invest heavily in the
backup moment (force acknowledgement, easy Emergency Kit, multiple recovery
authenticators/contacts).

---

## 17. Competitive security comparison (Bitwarden / 1Password / Proton Pass)

> Captures the "compare this vs Bitwarden vs 1Password vs Proton Pass on security"
> discussion. Caveat: SecureVault is assessed from this review; the others from their
> *published* security models (white papers, audits, OSS) — exact parameters evolve, so treat
> commercial specifics as "as documented."

### 17.1 At-a-glance

| Dimension | **SecureVault** | **Bitwarden** | **1Password** | **Proton Pass** |
|---|---|---|---|---|
| Zero-knowledge / E2E | ✅ web/Android (❌ iOS) | ✅ | ✅ | ✅ |
| KDF | Argon2id 64MB/t4 | PBKDF2-600k default; Argon2id optional | PBKDF2 + **Secret Key** | Argon2 / SRP key hierarchy |
| Cipher | AES-256-GCM | AES-256-CBC + HMAC | AES-256-GCM | AES-256-GCM |
| **Weak pwd survives server+DB breach?** | ❌ No | ❌ No | ✅ **Yes** (Secret Key) | ❌ No |
| Auth model | authHash + server PBKDF2 pepper | master-pwd hash (similar) | **SRP** | **SRP** |
| Open source | repo, **unaudited** | ✅ OSS, audited | ❌ closed (white paper + audits) | ✅ OSS clients, audited |
| Independent audits | ❌ none | ✅ recurring | ✅ recurring | ✅ |
| Bug bounty / security team | ❌ | ✅ | ✅ | ✅ |
| Known unpatched High/Critical | ✅ several | maintained | maintained | maintained |
| Maturity | early / single-dev | years, large scale | years, large scale | years, Proton ecosystem |

### 17.2 The dimension that actually separates them
**"Can a weak master password survive total server compromise?"**
- **1Password: Yes** — its **Secret Key** (128-bit, on-device, never sent to server) is
  combined with the master password. Strongest of the four for this threat — and exactly the
  upgrade described in §15.
- **Bitwarden, Proton Pass, SecureVault: No** — single secret derived from the master
  password. Strong KDF mitigates but doesn't eliminate weak-password-after-breach.

On *architecture alone*, SecureVault sits in the **same category as Bitwarden and Proton**
(single-secret, KDF-protected, zero-knowledge) and **behind 1Password** on this property.

### 17.3 Per product
- **Bitwarden** — strongest mix of transparency + trust: fully open source, audited,
  self-hostable, mature. Conservative crypto (AES-CBC+HMAC). No Secret Key. Real security team
  + bug bounty.
- **1Password** — strongest *threat model* via Secret Key + SRP (server never receives
  password-equivalent material). Closed source but detailed white paper + audits. Trade-off:
  Secret Key recovery/usability burden, closed client.
- **Proton Pass** — strong privacy posture (Swiss, open-source audited clients, SRP,
  integrated email aliases). Solid crypto. Single-secret, same weak-password caveat. Younger
  but backed by an established security org.
- **SecureVault** — respectable *design* (real zero-knowledge, Argon2id, AES-GCM, correct
  authz/IDOR, sensible lazy-KDF-upgrade, the one Critical fixed) but **not in the same league
  operationally**: iOS broken, extension weaknesses, MITM gaps, **no audit, no bug bounty,
  single-dev, early-stage**, several High findings open.

### 17.4 Honest verdict
- **For the "weak password + full breach" guarantee:** 1Password > (Bitwarden ≈ Proton ≈
  SecureVault-by-design). Only the Secret Key model wins here.
- **For overall real-world security *today*:** Bitwarden, 1Password, and Proton Pass are in a
  **different tier** than SecureVault — not because their core designs beat SecureVault's
  *intent*, but because they're audited, battle-tested, fully implemented across platforms,
  actively maintained, and free of known unpatched Critical/High issues.

**Put plainly: SecureVault's blueprint is competitive with Bitwarden/Proton; its current
implementation and operational maturity are not.** To close the gap: fix iOS + the extension,
get an independent audit, add cert pinning + a client KDF floor, and — to actually *beat* the
Bitwarden/Proton tier on the breach scenario — add the **Secret Key** (§15), which would put
it on par with 1Password's strongest property.
