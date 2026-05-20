# SecureVault — Security Fix Plan

A comprehensive roadmap to make SecureVault a robust, production-grade password manager. Ordered by **risk × user-impact**. Items marked ✅ are already fixed.

---

## Phase 0 — Stop the bleeding (ship-blocking)

These cause **data loss, false security claims, or trivial compromise**. Nothing else ships until fixed.

### 0.1 Fix encryption-salt rotation that destroys vault data ✅

**Problem**: `AuthService.changePassword()` used to generate a new `encryptionSalt`, making every existing vault entry permanently undecryptable.

**Fix**: Wrapped Data Encryption Key (DEK) model — vault key is wrapped with KEK derived from password. Password change re-wraps the same vault key with new KEK. Vault entries untouched.

**Status**: ✅ Already implemented. `wrappedVaultKey` + KEK model in place.

---

### 0.2 Fix 2FA login challenge binding

**Files**: `AuthController.java:108-120`, `AuthService.java:193-210`, `TwoFactorVerifyRequest.java:7-12`, `TwoFactorLoginResponse.java:28-33`

`POST /api/v1/auth/verify-2fa` accepts only `{email, code}` and then issues full access/refresh tokens if the TOTP code is valid. It is not bound to a password-authenticated login attempt, challenge token, session nonce, device, IP, or expiration. Possession of a current TOTP code is enough to log in as any email with 2FA enabled.

**Fix**:
- `POST /auth/login` verifies password first.
- If 2FA is enabled, return `{twoFactorRequired: true, challengeToken}` only.
- `challengeToken` must be short-lived, signed, single-purpose, and include user id, issued time, and nonce/jti.
- `POST /auth/verify-2fa` must require `{challengeToken, code}` and reject email-only verification.
- Store challenge nonce in Redis and invalidate on success/failure threshold.
- Rate-limit TOTP attempts per challenge, user, and IP.

---

### 0.3 Actually enforce 2FA at login

**Files**: `AuthService.java:166-174`, `TwoFactorLoginResponse.java:28-33`

Current password login no longer issues full JWT tokens when `twoFactorEnabled=true`, but it returns `encryptionSalt` and `wrappedVaultKey` before 2FA completes. That exposes key-wrapping material to anyone with the correct password but without the second factor, and it keeps the 2FA flow split from the challenge-binding fix above.

**Fix**: During the first login step, return only `twoFactorRequired`, `challengeToken`, and safe display metadata. Return tokens, `encryptionSalt`, and `wrappedVaultKey` only after challenge-bound 2FA verification succeeds. Add backup recovery codes (10 single-use, hashed at rest).

---

### 0.4 TOTP secret stored in plaintext

**File**: `User.java:80-81`

`twoFactorSecret` stored unencrypted. DB breach → attacker can generate valid TOTP codes for any user.

**Fix**: Encrypt TOTP secret at rest using AES-256-GCM with a server-side key. Decrypt only during code verification.

---

### 0.5 Upgrade client-side KDF (mobile)

**File**: `IosEntryEncryptor.kt` (throws `NotImplementedError`), `AndroidEntryEncryptor.kt:24-49`

Android already uses **Argon2id** (`t=3, m=64MB, p=4`) matching the backend. iOS is not implemented at all — throws `NotImplementedError`. No per-user KDF params stored for future upgrades.

**Fix**:
- Implement iOS KDF — use `argon2kt` (KMP) or iOS `CommonCrypto` PBKDF2 (600k iterations) as stopgap
- Store `kdf_type`, `kdf_iterations`, `kdf_memory_kb` in `User` entity, return in login response so client uses stored params instead of hardcoded ones

---

## Phase 1 — Critical hardening

### 1.1 Hash refresh tokens at rest ✅

**File**: `RefreshToken.java:48-49` (previously)

Raw JWT stored in DB. DB leak = all sessions hijackable.

**Fix**: Store SHA-256 hash instead. Lookup by hash.

**Status**: ✅ Fixed — `V5` migration, `tokenHash` field, `hashToken()` method in `AuthService`.

---

### 1.2 Password reuse prevention ✅

**File**: `AuthService.java:256-262` (previously)

History check re-hashed with a freshly generated salt, making comparison always fail. Users could reuse their last password.

**Fix**: Store salt alongside hash in password_history. Re-hash candidate with each entry's original salt before comparing.

**Status**: ✅ Fixed — `V4` migration, `passwordSalt` in `PasswordHistory`, correct comparison.

---

### 1.3 Per-endpoint, distributed rate limiting + trusted proxy handling

**Files**: `LoginRateLimiter.java:41-71`, `RateLimitingFilter.java:21-66`, `AuthController.java:208-214`

In-memory `ConcurrentHashMap` — all state lost on restart. Single global limit (60/min). Trusts `X-Forwarded-For` without validation — attackers spoof IP to bypass.

**Fix**:
- Move to Redis-backed token buckets
- Define per-endpoint limits:
  - `/auth/login`, `/auth/register`, `/auth/refresh`: 5/min per IP **and** per email
  - `/auth/verify-2fa`: 5/min per challenge token, user, and IP
  - `/auth/change-password`: 5/min per user
  - `/vault/**`: 120/min per user
  - default: 60/min per user
- Trust `X-Forwarded-For` / `X-Real-IP` only when `RemoteAddr` is a known reverse proxy; otherwise ignore forwarded headers
- Return `Retry-After` header on 429

---

### 1.4 Failed logins not audit-logged

**File**: `AuditService.java:106`, `AuthController.java:88-101`

`logFailedLogin()` is defined but never called anywhere. Failed brute-force attempts leave zero trace.

**Fix**: Call `auditService.logFailedLogin()` from `AuthService.login()` catch path before exception propagates.

---

### 1.5 Vault audit logs missing IP and User-Agent

**File**: `VaultController.java:69,108,131,151,169`

Every `logVaultAccess()` call passes `null, null` for IP and User-Agent. All vault CRUD audit entries lack forensic data.

**Fix**: Pass `httpRequest.getRemoteAddr()` and `httpRequest.getHeader("User-Agent")` to all vault audit log calls.

---

### 1.6 Weak JWT secret fallback ✅

**Files**: `.env:11`, `application.properties:20`, `application-prod.properties:20`

Default secret `SecureVaultSecretKeyForJWTTokenGeneration2024` is not random. Falls back to this string if env var not set.

**Fix**: Remove fallback defaults. Validate at startup that `JWT_SECRET` is ≥ 32 bytes. Generate using `openssl rand -base64 32`.

**Status**: ✅ Fixed — fallback removed from both property files. `JwtTokenProvider` now throws `IllegalArgumentException` at startup if `JWT_SECRET` is null or shorter than 32 chars.

---

### 1.7 Breach-corpus password validation ✅

**File**: `PasswordService.java:336-356`

`calculatePasswordStrength()` uses basic scoring (`Password1!` passes). NIST SP 800-63B requires breach-list checks.

**Fix**: Integrate HaveIBeenPwned k-anonymity API. Reject any password in breach corpus regardless of score. Optionally supplement with zxcvbn for entropy estimation.

**Status**: ✅ Fixed — `BreachCheckService` with HIBP k-anonymity API + offline common-passwords set (~200 entries). Wired into `register()` and `changePassword()`.

---

### 1.8 Short access-token TTL + revocation list

**Files**: `JwtTokenProvider.java:68-99`, `JwtAuthenticationFilter.java:65-74`, `AuthService.java:258-262`

Access tokens not revocable. Current TTL 1 hour. No `jti` claim. No blacklist.

**Fix**:
- Set access token TTL to 15 minutes
- Add `jti` (token ID) claim
- On security events (password change, logout-all), push `jti`s to Redis revocation list
- `JwtAuthenticationFilter` checks list on every request

---

### 1.9 Master password lifecycle in mobile memory

**Files**: `AndroidEntryEncryptor.kt:27-114`, mobile auth view models

The current Android implementation caches the vault key as a Base64 `String` in `AndroidEntryEncryptor.cachedVaultKey`. Login and unlock flows pass master passwords through immutable Kotlin `String`s in UI/view-model/repository layers. Immutable strings cannot be wiped and may remain in memory after lock/logout.

**Fix**: Derive KEK at unlock, hold raw key bytes or `SecretKey` only as long as necessary, discard password input immediately, and explicitly zero byte arrays where possible. Auto-lock on background after N minutes. Avoid Base64 strings for cached secrets. Use Android Keystore where possible.

---

### 1.10 Browser token and key-material storage

**Files**: `web/src/api/client.ts:20-35`, `web/src/context/AuthContext.tsx:49-58`, `web/src/context/VaultContext.tsx:72-85`

The web app stores access token, refresh token, `encryptionSalt`, and `wrappedVaultKey` in `localStorage`. Any XSS or malicious extension can steal long-lived session credentials and key-wrapping material. Even if vault contents remain encrypted, attackers can keep refreshing sessions and run offline guessing against the wrapped vault key.

**Fix**:
- Store refresh tokens in `HttpOnly; Secure; SameSite=Strict` cookies.
- Keep access tokens in memory only and use short TTLs.
- Keep `wrappedVaultKey` out of persistent browser storage where possible; re-fetch after authenticated login or keep only in session memory.
- Harden CSP and remove inline/script injection surfaces.
- Add automated XSS/static checks for React rendering paths.

---

## Phase 2 — Important hardening

### 2.1 Hardcoded production secrets in docker-compose.yaml

**File**: `docker-compose.yaml:24-28,43,57`

DB password, JWT secret, Redis password hardcoded in plaintext and committed.

**Fix**: Treat the committed values as compromised. Rotate DB password, Redis password, and JWT secret. Replace with `${VAR}` references. Inject via Dockploy env vars, Docker secrets, or a secret manager. If this repo was pushed/shared, purge secrets from Git history and invalidate old tokens.

---

### 2.2 `.env` not in `.gitignore`

**File**: `.gitignore`

`.env` is untracked but not ignored. One `git add .` commits all secrets.

**Fix**: Already added to `.gitignore` in this session — verify it's pushed.

---

### 2.3 Empty default DB password

**Files**: `application.properties:6`, `application-prod.properties:6`

`spring.datasource.password=${DB_PASSWORD:}` — defaults to empty string. Username defaults to `tanay`.

**Fix**: Remove empty default. Add startup check that fails if `DB_PASSWORD` is not set.

---

### 2.4 SSL/TLS not enforced

**Files**: `application.properties:34-40`, `application-prod.properties:34-40`, `web/nginx.conf:1-20`, `mobile/app/src/androidMain/kotlin/com/securevault/mobile/di/AppModule.kt:31`, `mobile/app/src/androidMain/res/xml/network_security_config.xml:3-10`

Backend SSL defaults to disabled and `security.require-ssl` defaults to false. The web container listens on port 80 behind a presumed reverse proxy. The Android app hardcodes `http://192.168.1.38:8080` and the network security config permits cleartext traffic globally.

**Fix**:
- Enforce HTTPS at Traefik/reverse proxy with HTTP-to-HTTPS redirects and HSTS.
- Set production `REQUIRE_SSL=true` and document the required proxy TLS setup.
- Move mobile base URL to environment/flavor config.
- Make Android cleartext traffic debug-only; release builds must use HTTPS.
- Consider mobile certificate pinning after stable production TLS is in place.

---

### 2.5 Swagger enabled in `.env` defaults

**File**: `.env:18`

`SWAGGER_ENABLED=true` in checked-in `.env`. Risk of deploying with public API docs.

**Fix**: Set default to `false`. Enable only in dev profiles.

---

### 2.6 No size and format limits on vault entry payloads

**File**: `VaultEntryRequest.java`

`encryptedData` and `iv` have `@NotBlank` but no `@Size` constraint, Base64 validation, or IV length validation. Invalid ciphertext can be stored indefinitely and oversized payloads can be used for storage exhaustion.

**Fix**: Add `@Size(max = ...)` constraints (for example 64KB encrypted data), Base64 validators, exact 12-byte decoded IV validation for AES-GCM, and server request body limits.

---

### 2.7 No 2FA enforcement on sensitive operations

**Files**: `TwoFactorController.java:97-105`, `VaultController.java:163-170`, `AuthController.java:183-205`, device controller

Password changes, 2FA disable, device registration/removal, and `DELETE /vault` have no recent re-auth or 2FA re-verification. A stolen bearer token can disable protections or destructively delete vault data.

**Fix**: Require recent re-auth or TOTP re-verification for sensitive operations. Issue a 5-minute elevated/sudo token after successful step-up and require it for destructive/security-sensitive endpoints.

---

### 2.8 JWT signing key rotation

**File**: `JwtTokenProvider.java`

Single static HMAC secret. No rotation, no `kid` header.

**Fix**: Add `kid` header. Maintain JWKS with overlapping validity windows. Build rotation runbook. Optionally migrate to RS256/EdDSA for multi-service deployments.

---

### 2.9 Move secrets to secret manager

**Files**: `.env`, docker-compose.yaml

Secrets in env vars. No rotation, no audit, leak-prone in container inspection.

**Fix**: Integrate AWS Secrets Manager / GCP Secret Manager / HashiCorp Vault. Load at startup via Spring Cloud Config. Rotate JWT secret 90d, DB password 180d.

---

### 2.10 Structured entry encoding (mobile)

**Files**: `AndroidEntryEncryptor.kt:117-149`, web crypto entry format

Older docs mention pipe-delimited payloads. Current Android and web clients encrypt JSON payloads, which is better, but the server stores no explicit encrypted-payload schema/version beyond `VaultEntry.version=1`, and clients parse independently.

**Fix**: Standardize encrypted plaintext schema (`{"v":1,"name":...}`), document it, and keep a clear migration path. Ensure Android, iOS, and web use the same schema and validation expectations.

---

### 2.11 Certificate pinning (mobile)

**File**: Mobile network layer

No pinning. Rogue CA or user-installed root CA can MitM TLS.

**Fix**: Pin production server certificate via Ktor `CertificatePinner` (Android) and `URLSession` pinning (iOS). Pin two certs for rotation. Provide kill-switch config endpoint.

---

### 2.12 Android backup and local database hardening

**Files**: `AndroidManifest.xml:6-10`, `SecureVaultDatabase.kt:24-48`, `DatabaseKeyManager.kt`

`android:allowBackup="true"` is enabled for a vault app. Android Auto Backup or device-transfer paths can copy app data. The encrypted SQLCipher path exists, but `SecureVaultDatabase.getInstance(context)` can create the database without SQLCipher if used accidentally. Destructive migrations are enabled for both encrypted and unencrypted builders.

**Fix**:
- Set `android:allowBackup="false"` for release builds, or define strict `dataExtractionRules` that exclude vault/session data.
- Remove or restrict the no-passphrase database builder.
- Avoid `fallbackToDestructiveMigration()` for production vault data; provide explicit migrations.
- Add tests that assert SQLCipher is always used in production wiring.

---

### 2.13 TOTP secret lifecycle during setup

**Files**: `TwoFactorAuthService.java:64-77`, `TwoFactorController.java:55-84`

`GET /2fa/setup` immediately stores the newly generated TOTP secret before the user verifies setup. If the user abandons setup, a valid secret remains stored while `twoFactorEnabled=false`. This is not as severe as plaintext storage, but it complicates lifecycle and cleanup.

**Fix**: Store pending setup secrets separately with short TTL, encrypted at rest. Promote the pending secret to active only after code verification. Clear stale pending secrets.

---

### 2.14 Zero-knowledge architecture gap

**Files**: `AuthService.java:86-122`, `AuthService.java:328-341`, `PasswordService.java:221-277`

The server receives the master password during registration/login and can generate, derive, wrap, and in fallback flows unwrap vault-key material. That is common for many apps but weaker than the project's zero-knowledge claims.

**Fix**: Move vault-key generation and wrapping fully client-side. Keep server authentication separate from vault encryption, ideally using a hardened verifier flow or PAKE-style protocol. Never implement server-side fallback unwrap for vault keys in production.

---

### 2.15 Audit log hardening

**File**: `AuditLog.java`, `AuditService.java`

Raw IP stored (GDPR concern). No integrity protection.

**Fix**: Hash IPs with daily-rotating HMAC key. Append-only DB constraint (revoke UPDATE/DELETE on table from app role). Optionally chain entries with `prev_hash` for tamper-evidence. Define retention policy (90d security events, 30d benign).

---

## Phase 3 — Defense in depth

### 3.1 Argon2id parameter tuning

Bump to 96MB memory (closer to 1Password's 100MB). Store params per-user for future upgrades. Background re-hash on next login when params change.

---

### 3.2 Optional "secret key" (1Password-style)

128-bit random value generated at signup, never sent to server. Combined with master password for KDF input. Defends against weak master passwords.

---

### 3.3 Security headers + CSP

**Files**: `SecurityHeadersFilter.java:21-37`, `web/nginx.conf:8-12`, `web/index.html:7-9`

Backend and web nginx set CSP and security headers, but policies differ. Backend `script-src 'self'` may break WASM clients if serving the SPA through Spring, while nginx allows `wasm-unsafe-eval`. Web `index.html` loads Google Fonts, but nginx CSP only allows `font-src 'self'` and `style-src 'self' 'unsafe-inline'`, so production may block those external font requests.

**Fix**: Define one production CSP for the actual deployment path. Remove external font dependencies or explicitly allow required origins. Prefer self-hosted fonts. Keep `frame-ancestors 'none'`, `base-uri 'self'`, `form-action 'self'`, and strict `connect-src`.

---

### 3.4 Replay protection (sudo mode)

For `/auth/change-password`, `/2fa/disable`, `/vault DELETE all`: require fresh authentication challenge. Issue 5-minute elevated token.

---

### 3.5 Device binding & session management

Wire up existing `Device` entity: register device fingerprint on login, list active sessions, allow revoke-per-device, email notification on new device.

---

### 3.6 Encrypted database backups

`pg_dump` → encrypt with KMS key → store in S3 with object lock. Restore drills quarterly.

---

### 3.7 Dependency & supply chain

Dependabot/Renovate for automated updates. OWASP Dependency-Check in CI (fail on CVSS ≥ 7). Pin Maven Central checksums.

---

### 3.8 Static analysis & secret scanning

Semgrep/CodeQL in CI with security ruleset. Gitleaks as pre-commit hook + CI check.

**Current trigger**: `docker-compose.yaml` already contains committed secrets. Add Gitleaks immediately and fail CI on secret findings.

---

### 3.9 Dependency verification status

**Current check**: `npm audit --audit-level=moderate` reported `0 vulnerabilities`.

**Fix**: Keep Dependabot/Renovate enabled for npm, Maven, and Gradle. Add OWASP Dependency-Check or osv-scanner in CI. Run audits in CI on every PR.

---

### 3.10 Mobile test/build health

**Current check**: `mobile ./gradlew test` fails before tests run because `mobile/app/src/androidUnitTest/kotlin/com/securevault/mobile/data/local/CryptoEngine.kt` has duplicate `getCachedVaultKey()` definitions and unresolved `Json`.

**Fix**: Repair mobile unit-test compilation, then add tests for vault-key cache clearing, encrypted database initialization, cleartext-disabled release config, and Android backup/data extraction rules.

---

## Phase 4 — Operational maturity (ongoing)

| Item | Why |
|------|-----|
| Third-party penetration test | Independent verification before GA |
| Bug bounty program (HackerOne) | Continuous external scrutiny |
| SOC 2 Type II roadmap | Required by enterprise customers |
| Incident response runbook | Pre-defined steps for token leak, DB compromise |
| Security training for contributors | Most vulns come from well-meaning code |
| Threat model in repo | Forces explicit reasoning about new features |
| Quarterly key-rotation drills | Verify rotation works before you need it |
| Monitoring & alerting | Failed logins, lockouts, 429s, JWT failures |
| Signed mobile releases | Prevents APK swap attacks |
| Reproducible mobile builds | Users verify binary matches source |
| Secret rotation after leaks | Rotate DB/Redis/JWT secrets immediately after any repo exposure |
| Release security checklist | Verify TLS, mobile cleartext disabled, backup disabled, Swagger disabled |

---

## Summary

| Phase | Total items | ✅ Fixed | ❌ Remaining |
|-------|-------------|----------|--------------|
| Phase 0 — Stop the bleeding | 5 | 1 | 4 |
| Phase 1 — Critical hardening | 10 | 4 | 6 |
| Phase 2 — Important hardening | 15 | 0 | 15 |
| Phase 3 — Defense in depth | 10 | 0 | 10 |
| Phase 4 — Operational maturity | 12 | 0 | 12 |
| **Total** | **52** | **5** | **47** |

### Already fixed ✅
- 0.1 DEK/wrapped vault key model
- 1.1 Refresh token hashing (SHA-256)
- 1.2 Password reuse prevention (salt-aware comparison)
- 1.6 JWT secret fallback removed (startup validation enforces ≥ 32 chars)
- 1.7 Breach-corpus validation (HIBP k-anonymity + offline common-passwords set)

### Latest review verification
- Backend `mvn -q test`: passed.
- Web `npm audit --audit-level=moderate`: 0 vulnerabilities.
- Mobile `./gradlew test`: failed due unit-test compile errors in `CryptoEngine.kt` (`getCachedVaultKey()` conflict, unresolved `Json`).
