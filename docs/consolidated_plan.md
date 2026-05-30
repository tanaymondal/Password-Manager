# SecureVault — Consolidated Fix Plan

Generated from `SECURITY_AND_CRYPTO_CORE.md` + `need_to_fix.md` + local repo audit.
**Key finding**: The `upgrade-kdf` fix and `crypto-core` crate described in `SECURITY_AND_CRYPTO_CORE.md` were written on another machine and are **NOT** present in this working tree. All items below are unfixed here.

---

## Critical — upgrade-kdf (C1/C2 from SECURITY_AND_CRYPTO_CORE.md)

These were "fixed" in the markdown doc but **not applied locally**. Need to implement:

- **C1 — Add `@RequireSudo` to `AuthController.upgradeKdf()`**
  `src/main/java/com/securevault/controller/AuthController.java:222`
- **C2 — Add KDF bounds to `UpgradeKdfRequest`**
  `src/main/java/com/securevault/dto/UpgradeKdfRequest.java`
  Add `@Size`, `@Min`/`@Max` on iterations (1–100), memory (8192–1048576), parallelism (1–16)
- **Web: `upgradeKdf()` needs `sudoToken` parameter**
  `web/src/api/auth.ts:63`
- **Web: `VaultContext.tsx` needs sudo flow before calling upgrade-kdf**
  Derive current auth hash with old params → `requestSudo()` → pass token to `upgradeKdf()`

---

## New findings from SECURITY_AND_CRYPTO_CORE.md §2 (not in need_to_fix.md)

### Backend — High
- **H3 — Sudo token accepted via query/body param** (`SudoAspect.java:33`)
  Should be header-only (`X-Sudo-Token`). Currently also reads `sudo_token` request param → leaks into logs/history/Referer.
- **H4 — TOTP brute-force surface** (`AuthService.java:243`)
  Per-challenge cap of 5 is bypassable by re-issuing a challenge (re-submit password). No durable per-user TOTP-verify lock.

### Backend — Medium
- **M1 — CSRF disabled with cookie-based refresh** (`SecurityConfig.java:50`)
  Only `SameSite=Strict` protects `/refresh`. Add origin check / defense-in-depth.
- **M3 — User enumeration via `prelogin` timing** (`AuthService.java:138`)
  Real DB salt lookup vs random salt generation for unknown users. `login` is timing-hardened but `prelogin` is not.
- **M5 — Denylist TTL can be 0** (`JwtAuthenticationFilter.java:138`)
  Redis rejects non-positive EX near token expiry.

### Backend — Low
- Default Argon2id `t=4 / 64MB / 4` on low end of OWASP guidance
- HSTS only in `prod` profile; `REQUIRE_SSL` defaults false; no fail-fast on missing TLS
- `SudoService.revokeAllForUser` uses blocking `KEYS` scan (can block Redis)

### Web & Extension — Critical
- **W-C1 — Extension auto-fills on `http://`** (`manifest.json:24`, `content.ts:107`)
  Drop `http://*` from matches, never autofill on insecure origins.
- **W-C2 — Extension stores refresh token in `chrome.storage.local`** (`storage.ts:32`)
  Persists unencrypted on disk. Use `chrome.storage.session`.

### Web & Extension — High
- **W-H1 — Weak domain matching for autofill** (`background.ts:41`)
  Naive `www.`-strip, no scheme/port check.
- **W-H2 — No origin/sender validation on extension messages** (`background.ts:49`)
  Any frame can request decrypted entries / write clipboard.

### Web & Extension — Medium
- **W-M1 — No client-side KDF floor** (`VaultContext.tsx:116`)
  Trusts server/prelogin KDF params verbatim. A MITM could return `iterations:1`.
- **W-M2 — Extension has no auto-lock at all** (`useAutoLock.ts:22`)
  Web has weak auto-lock (no `visibilitychange`/`blur` lock).
- **W-M3 — Master password crosses popup→background as raw value** (`script.ts:108`, `background.ts:94`)

### Mobile — Critical (iOS)
- **M-C1 — iOS AES-GCM provides no authentication** (`CryptoEngine.ios.kt:88,133`)
  Uses `CCCrypt` one-shot API which does NOT implement authenticated GCM. No tag produced or verified. Reimplement with CryptoKit `AES.GCM`.
- **M-C2 — iOS KEK uses PBKDF2 with low iterations** (`CryptoEngine.ios.kt:46`)
  Uses `kCCPBKDF2` with `kdfIterations` (default **4**). PBKDF2 @ 4 iterations is trivially crackable. Need Argon2id matching Android.
- **M-C3 — iOS has no secure storage** (`SessionManager.kt`)
  Imports Android-only `EncryptedSharedPreferences`. No iOS Keychain implementation.

### Mobile — High
- **M-H1 — iOS ships `http://localhost:8080`** (`iosMain/di/AppModule.kt:14`)
- **M-H2 — iOS `IosEntryEncryptor.decrypt` returns empty fields** (`IosEntryEncryptor.kt:101`)
- **M-H3 — No client-side KDF floor on mobile** (`AuthRepositoryImpl.kt:91`)
- **M-H4 — No TLS certificate pinning** (`SecureVaultApi.kt:388`)

### Mobile — Medium
- **M-M1 — Local SQLCipher key not auth-gated** (`DatabaseKeyManager.kt:60`)
  Keystore master key has no `setUserAuthenticationRequired`. Recoverable on rooted device. Title/username cached unencrypted.
- **M-M2 — Weak Android auto-lock** (`AndroidEntryEncryptor.kt:29`)
  5-min `Handler`, doesn't survive backgrounding/process death.
- **M-M3 — `isUnauthorized` substring-matches exception text** (`SecureVaultApi.kt:322`)

---

## Unfixed items from need_to_fix.md

### Phase 1 — Critical hardening
- **1.11 — CAPTCHA + email verification** on registration/login
- **1.17 / 2.11 — Mobile certificate pinning** (Android + iOS)
- **1.20 — CORS credential + origin patterns** (`CorsConfig.java:17`)

### Phase 2 — Important hardening
- **2.8 — JWT signing key rotation** (no `kid` header, no JWKS)
- **2.9 — Move secrets to secret manager** (env vars → AWS Secrets Manager / Vault)
- **2.10 — Structured entry encoding (mobile)** — server stores no encrypted-payload schema
- **2.22 — `Permissions-Policy` missing modern directives** (interest-cohort, browsing-topics, attribution-reporting)
- **2.28 — Extension content script runs on all pages** (`manifest.json:26`)

### Phase 3 — Defense in depth
- **3.2 — Optional "secret key"** (1Password-style, 128-bit)
- **3.5 — Device binding & session management** (wire up existing Device entity)
- **3.6 — Encrypted database backups** (pg_dump → KMS → S3 object lock)
- **3.7 — Dependency & supply chain** (Dependabot exists but deps still outdated on mobile: Ktor 2.3.7, etc.)
- **3.11 — No Play Integrity / App Attest / root detection**
- **3.15 — Logout rate limit** (unauthenticated logout: 3 per 5min via Redis — marked ✅ in header but ❌ in status, verify)
- **3.24 — `Cache-Control: no-store` verify in production**

---

## Crypto-core migration (from SECURITY_AND_CRYPTO_CORE.md §4, §10)

### Phase 0 — Finalize & freeze the core contract
- [ ] Confirm Android's authHash salt encoding matches web (UTF-8 string bytes vs base64-decoded)
- [ ] Unify entry-plaintext JSON (canonical, stable key order) into the core
- [ ] Lock `DEFAULT_PARAMS` / `MIN_PARAMS` and `validate_params` call sites
- [ ] Commit `Cargo.lock`

### Phase 1 — Prove parity (hard gate)
- [ ] Create `crypto-core/` directory and all source files from `SECURITY_AND_CRYPTO_CORE.md §6`
- [ ] Create `test-vectors/` directory and generator from `SECURITY_AND_CRYPTO_CORE.md §7`
- [ ] Install Rust toolchain if not present
- [ ] `cd test-vectors && npm i hash-wasm && node generate.mjs > vectors.json`
- [ ] `cd crypto-core && cargo test` — all vectors green (KDF + envelopes)
- [ ] Android oracle: confirm `argon2kt` matches vectors

### Phase 2 — Build & binding infrastructure
- [ ] Web: `wasm-bindgen` exports + `wasm-pack build --target web`
- [ ] Mobile: UniFFI interface → Kotlin + Swift
- [ ] Android: `cargo-ndk` → `.so` for arm64-v8a, armeabi-v7a, x86_64
- [ ] iOS: per-target static libs → XCFramework
- [ ] CI: build all artifacts + run vectors through bindings

### Phase 3 — Web integration
- [ ] Wrap wasm behind existing `web/src/crypto/{argon2,vaultKey,entries,util}.ts`
- [ ] Feature-flag; shadow-diff old TS vs new wasm
- [ ] Verify register → login → unlock → CRUD → change-password → upgrade-kdf
- [ ] Delete old TS crypto impls (keep thin wrappers)

### Phase 4 — Android integration
- [ ] Replace bodies in `AndroidEntryEncryptor.kt` and `CryptoEngine.android.kt` with UniFFI calls
- [ ] Run Argon2 off main thread
- [ ] Verify against existing real Android vault
- [ ] Delete old Kotlin crypto

### Phase 5 — iOS integration (the fix)
- [ ] Replace `CryptoEngine.ios.kt` + `IosEntryEncryptor.kt` with UniFFI binding
- [ ] Verify iOS unlocks/decrypts vaults written by web/Android
- [ ] Implement Keychain-backed `SessionManager` for iOS

### Phase 6 — Browser extension
- [ ] Point `web/extension/src/lib/{argon2,vaultKey,entries}.ts` at same wasm module

### Phase 7 — Rollout & production verification
- [ ] Staged rollout per platform, each behind flag with rollback path
- [ ] Monitor decrypt/unlock-failure rates

### Phase 8 — Cleanup & guardrails
- [ ] Delete duplicated client constants; source from core
- [ ] Keep server crypto untouched (zero-knowledge boundary)
- [ ] Vector suite as required CI check on every platform

---

## Summary by priority

| Priority | Area | Items |
|----------|------|-------|
| 🔴 P0 | **upgrade-kdf fix** (C1/C2) | 4 files to patch — NOT applied locally |
| 🔴 P0 | **iOS crypto broken** (M-C1, M-C2, M-C3, M-H1, M-H2) | 5 critical/high iOS issues |
| 🔴 P1 | **Extension security** (W-C1, W-C2, W-H1, W-H2, 2.28) | 5 items, incl. http:// autofill + plaintext token on disk |
| 🟡 P2 | **Backend hardening** (H3, H4, M1, M3, M5, 1.11, 1.20, 2.8, 2.9, 2.22) | 10 items |
| 🟡 P2 | **Mobile hardening** (M-M1, M-M2, M-M3, 1.17/2.11, 2.10, 3.11) | 6 items |
| 🟡 P2 | **Web hardening** (W-M1, W-M2, W-M3, 3.24) | 4 items |
| 🟢 P3 | **Secret key** (3.2), **Device binding** (3.5), **Backups** (3.6), **Deps** (3.7), **Logout rate limit** (3.15) | 5 items |
| 🔵 P4 | **Crypto-core migration** | 8 phases, replaces per-platform crypto with single Rust core |

**Total: ~40+ items** (the 21 from need_to_fix + ~15 new from SECURITY_AND_CRYPTO_CORE.md + ~8 crypto-core phases)
