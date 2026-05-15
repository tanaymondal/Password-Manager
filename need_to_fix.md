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

### 0.2 Fix 2FA setup — completely broken

**Files**: `TwoFactorController.java:82`, `TwoFactorAuthService.java:111-121`, `Enable2FARequest.java`

`enable2FA()` is called with `secret=null`. `verifyCode()` checks the stored secret (null at setup → returns false). `Enable2FARequest` has no `secret` field. 2FA can never be enabled by any user.

**Fix**: Add `secret` field to `Enable2FARequest`. Pass the generated secret from `/setup` to `/enable`. Verify code against the provided secret, not the stored one.

---

### 0.3 Actually enforce 2FA at login

**File**: `AuthService.java:149-151`

`AuthService.login()` logs `"2FA required"` but issues full JWT tokens anyway. 2FA check has zero effect.

**Fix**: Two-step login:
1. `POST /auth/login` — if `twoFactorEnabled`, return `{requires2FA: true, challengeToken: <short-lived JWT>}` instead of tokens
2. `POST /auth/login/2fa` — accepts `{challengeToken, totpCode}` → validates → returns full tokens
3. Add backup recovery codes (10 single-use, hashed at rest)
4. Rate-limit TOTP attempts (5/min per challenge token)

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

### 1.3 Per-endpoint, distributed rate limiting

**Files**: `LoginRateLimiter.java`, `RateLimitingFilter.java`

In-memory `ConcurrentHashMap` — all state lost on restart. Single global limit (60/min). Trusts `X-Forwarded-For` without validation — attackers spoof IP to bypass.

**Fix**:
- Move to Redis-backed token buckets
- Define per-endpoint limits:
  - `/auth/login`, `/auth/register`, `/auth/refresh`: 5/min per IP **and** per email
  - `/auth/change-password`: 5/min per user
  - `/vault/**`: 120/min per user
  - default: 60/min per user
- Validate `X-Forwarded-For` against trusted proxy list; fall back to `RemoteAddr`
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

**File**: `JwtTokenProvider.java`

Access tokens not revocable. Current TTL 1 hour. No `jti` claim. No blacklist.

**Fix**:
- Set access token TTL to 15 minutes
- Add `jti` (token ID) claim
- On security events (password change, logout-all), push `jti`s to Redis revocation list
- `JwtAuthenticationFilter` checks list on every request

---

### 1.9 Master password lifecycle in mobile memory

**File**: Mobile `SessionManager`

`getMasterPassword()` returns a `String` held indefinitely. Immutable String can't be wiped. Memory dump exposes everything.

**Fix**: Derive KEK at unlock, hold derived key bytes, discard password string. Explicit `clear()` to zero bytes. Auto-lock on background after N minutes. Use Android Keystore where possible.

---

## Phase 2 — Important hardening

### 2.1 Hardcoded production secrets in docker-compose.yaml

**File**: `docker-compose.yaml:17-21,36,50`

DB password, JWT secret, Redis password hardcoded in plaintext and committed.

**Fix**: Replace with `${VAR}` references. Inject via Dockploy env vars or `.env` file. Remove from version control.

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

**Files**: `.env:17`, `application.properties:34`, `application-prod.properties:34`

`REQUIRE_SSL=false`, `server.ssl.enabled=${SSL_ENABLED:false}`. Credentials travel in plaintext without reverse proxy TLS.

**Fix**: Set `REQUIRE_SSL=true` in `.env.example`. Ensure Traefik/reverse proxy enforces HTTPS.

---

### 2.5 Swagger enabled in `.env` defaults

**File**: `.env:18`

`SWAGGER_ENABLED=true` in checked-in `.env`. Risk of deploying with public API docs.

**Fix**: Set default to `false`. Enable only in dev profiles.

---

### 2.6 No size limits on vault entry payloads

**File**: `VaultEntryRequest.java`

`encryptedData` and `iv` have `@NotBlank` but no `@Size` constraint. Storage exhaustion attack.

**Fix**: Add `@Size(max = ...)` constraints (e.g. 64KB encrypted data, reasonable limit for IV).

---

### 2.7 No 2FA enforcement on sensitive operations

**Scope**: All controllers

Password changes, device registration, vault access have no 2FA re-verification. Stolen JWT bypasses 2FA entirely.

**Fix**: Require TOTP re-verification for sensitive operations (password change, disable 2FA, new device registration).

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

**File**: Mobile `EntryEncryptor`

Pipe-delimited format (`title|username|password|...`) — any `|` in a field corrupts the entry.

**Fix**: Encrypt JSON-serialized entry with versioned schema (`{"v":1,"title":...,"username":...}`). Add `schema_version` field.

---

### 2.11 Certificate pinning (mobile)

**File**: Mobile network layer

No pinning. Rogue CA or user-installed root CA can MitM TLS.

**Fix**: Pin production server certificate via Ktor `CertificatePinner` (Android) and `URLSession` pinning (iOS). Pin two certs for rotation. Provide kill-switch config endpoint.

---

### 2.12 Audit log hardening

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

Content-Security-Policy, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `X-Content-Type-Options: nosniff`.

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

---

## Summary

| Phase | Total items | ✅ Fixed | ❌ Remaining |
|-------|-------------|----------|--------------|
| Phase 0 — Stop the bleeding | 5 | 1 | 4 |
| Phase 1 — Critical hardening | 9 | 4 | 5 |
| Phase 2 — Important hardening | 12 | 0 | 12 |
| Phase 3 — Defense in depth | 8 | 0 | 8 |
| Phase 4 — Operational maturity | 10 | 0 | 10 |
| **Total** | **44** | **5** | **39** |

### Already fixed ✅
- 0.1 DEK/wrapped vault key model
- 1.1 Refresh token hashing (SHA-256)
- 1.2 Password reuse prevention (salt-aware comparison)
- 1.6 JWT secret fallback removed (startup validation enforces ≥ 32 chars)
- 1.7 Breach-corpus validation (HIBP k-anonymity + offline common-passwords set)
