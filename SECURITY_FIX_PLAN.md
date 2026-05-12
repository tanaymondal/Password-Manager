# Production-Grade Security Fix Plan

A phased roadmap, ordered by **risk × user-impact**. Each item lists what's broken, what to do, where it lives, and rough effort.

---

## Phase 0 — Stop the bleeding (week 1, blocking for any prod release)

These three issues cause **data loss, false security claims, or trivial credential brute-force**. Nothing else ships until these are fixed.

### 0.1 Fix the encryption-salt rotation that destroys vault data
- **Problem**: `AuthService.changePassword` (`src/main/java/com/securevault/service/AuthService.java:147`) generates a new `encryptionSalt`. Every existing vault entry becomes permanently undecryptable.
- **Fix**: Introduce a **wrapped Data Encryption Key (DEK)** model.
  - At registration: generate a random 32-byte DEK; derive a Key Encryption Key (KEK) from the master password; store `wrappedDEK = AES-GCM(DEK, KEK)`.
  - All vault entries are encrypted under the **DEK**, not under a KEK derived from the password.
  - On password change: derive new KEK, re-wrap DEK, update `wrappedDEK`. Vault data is untouched.
- **Touches**: `User` entity (add `wrapped_dek`, `dek_iv`), `AuthService.register/changePassword`, mobile `EntryEncryptor`, `SessionManager`.
- **Migration**: needs a one-time client-side migration for existing users — derive old key, decrypt all entries, re-encrypt under new DEK. Plan an unlock-time migration flow.
- **Effort**: 3–5 days, plus migration testing.

### 0.2 Actually enforce 2FA at login
- **Problem**: `AuthService.login` (`src/main/java/com/securevault/service/AuthService.java:83`) only logs `"2FA required"` and issues full tokens anyway.
- **Fix**: Two-step login flow.
  - Step 1: `POST /auth/login` — if `twoFactorEnabled`, return `{requires2FA: true, challengeToken: <short-lived JWT, scope=2fa-only>}` instead of access tokens.
  - Step 2: `POST /auth/login/2fa` — accepts `{challengeToken, totpCode}`, validates TOTP via existing `TwoFactorAuthService`, returns full tokens.
  - Add **backup recovery codes** (10 single-use codes generated at 2FA enrollment, hashed at rest).
  - Rate-limit TOTP attempts independently (5/min per challenge token).
- **Touches**: `AuthController`, `AuthService`, new `TwoFactorChallenge` entity or in-memory cache, mobile login flow.
- **Effort**: 2–3 days.

### 0.3 Upgrade client-side KDF
- **Problem**: PBKDF2-SHA256 with 65,536 iterations (`mobile/app/src/androidMain/kotlin/com/securevault/mobile/data/local/AndroidEntryEncryptor.kt:25`) — below OWASP 2023 minimum (600k for PBKDF2) and weaker than competitors.
- **Fix**: Switch to **Argon2id** on the client (`m=64MB, t=3, p=4`), matching the backend. Use a Kotlin Multiplatform Argon2 binding (e.g. `argon2-kt`, libsodium bindings, or a JNI wrap of the same BouncyCastle the backend uses).
  - If Argon2 isn't viable on iOS in your timeline, bump PBKDF2 to **600,000 iterations** as a stopgap.
  - Store the KDF parameters in the user record (`kdf_type`, `kdf_iterations`, `kdf_memory`) so future upgrades don't break old vaults.
- **Touches**: `EntryEncryptor` (common + per-platform impls), `User` entity (KDF params), login response (return KDF params alongside salt).
- **Effort**: 3–4 days (more if iOS doesn't have a clean Argon2 binding).

---

## Phase 1 — Critical hardening (weeks 2–3)

### 1.1 Hash refresh tokens at rest
- **Problem**: `RefreshToken` rows store the raw JWT. DB leak = every active session hijackable.
- **Fix**: Store `SHA-256(token)` in DB. Lookup compares hashes. Original token only ever lives in the client.
- **Touches**: `RefreshToken` entity, `RefreshTokenRepository`, `AuthService.refreshToken/logout`.
- **Effort**: half a day.

### 1.2 Per-endpoint, distributed rate limiting
- **Problem**: `RateLimitingFilter` is in-process, single global limit (60/min per IP), trusts `X-Forwarded-For` blindly. Won't survive >1 backend instance.
- **Fix**:
  - Move to **Redis-backed token buckets** (e.g. Bucket4j with Redis, or Resilience4j).
  - Define **per-endpoint limits**:
    - `/auth/login`, `/auth/register`, `/auth/refresh`: 5/min per IP **and** per email
    - `/auth/login/2fa`: 5/min per challenge token
    - `/vault/**`: 120/min per user
    - default: 60/min per user
  - Validate `X-Forwarded-For` against a configured trusted-proxy list; otherwise use `RemoteAddr`.
  - Return `Retry-After` header on 429.
- **Touches**: `RateLimitingFilter` (rewrite), `application.yml` (proxy list), infra (add Redis).
- **Effort**: 2 days + Redis ops setup.

### 1.3 Breach-corpus password validation
- **Problem**: `calculatePasswordStrength` (`src/main/java/com/securevault/service/PasswordService.java:105`) passes `Password1!`. NIST SP 800-63B requires breach-list checks.
- **Fix**:
  - Integrate **HaveIBeenPwned k-anonymity API** (`/range/{first5sha1}`) for online check.
  - Optionally pre-load a top-100k breached-password bloom filter for offline check (no external dependency at registration time).
  - Reject any password appearing in the corpus, regardless of strength score.
  - Drop the score-based gate, or supplement with **zxcvbn** (real entropy estimation).
- **Touches**: `PasswordService`, new `BreachCheckService`, `register`/`changePassword` validation.
- **Effort**: 2 days.

### 1.4 Short access-token TTL + revocation list
- **Problem**: Access tokens are not revocable. If `app.jwt.expiration` is hours-long, a leak is uncapped.
- **Fix**:
  - Set access token TTL to **15 minutes** (config `app.jwt.expiration: 900000`).
  - Add `jti` (token ID) claim to access tokens.
  - On security events (password change, logout-all, account compromise), push `jti`s to a Redis **revocation list** with TTL = remaining token lifetime.
  - `JwtAuthenticationFilter` checks the list on every request (cheap Redis GET).
- **Touches**: `JwtTokenProvider`, `JwtAuthenticationFilter`, `AuthService` (logout/changePassword), config.
- **Effort**: 1.5 days.

### 1.5 Master password lifecycle in mobile memory
- **Problem**: `SessionManager.getMasterPassword()` returns a `String` held indefinitely. Memory dump on a compromised device exposes everything; immutable `String` can't be wiped.
- **Fix**:
  - At unlock: derive KEK once, hold the **derived key bytes** (`ByteArray`/`SecretKeySpec`), discard the password string immediately.
  - Wrap the key in a class with explicit `clear()` that zeroes the byte array.
  - Auto-lock the vault on app background after **N minutes** (configurable, default 5).
  - On lock: zero key material, force re-derivation on next unlock.
  - Use Android Keystore-backed key storage where possible (StrongBox/TEE).
- **Touches**: `SessionManager`, `AndroidEntryEncryptor`, app lifecycle handlers, settings screen.
- **Effort**: 3 days.

---

## Phase 2 — Important hardening (weeks 4–6)

### 2.1 JWT signing key rotation + asymmetric option
- **Problem**: Single static HMAC secret, no rotation, no `kid` header.
- **Fix**:
  - Add `kid` header to all issued JWTs.
  - Maintain a **JWKS** (key set) with overlapping validity windows — old keys verify, new keys sign.
  - Build a rotation runbook: generate new key → deploy as "next" → flip "current" → retire old after max token TTL.
  - For multi-service deployments later, switch to **RS256/EdDSA** so verifying services don't hold the signing key.
- **Touches**: `JwtTokenProvider`, key storage (env vars → secret manager), ops runbook.
- **Effort**: 2 days for HMAC rotation, +2 days for asymmetric migration.

### 2.2 Move secrets out of env vars into a secret manager
- **Problem**: `JWT_SECRET`, `DB_PASSWORD` in `.env` / env vars. No rotation, no audit, leak-prone in container inspection.
- **Fix**:
  - Integrate **AWS Secrets Manager / GCP Secret Manager / HashiCorp Vault**.
  - Use Spring Cloud Config or direct SDK; load at startup, optionally refresh.
  - Document rotation cadence: JWT secret 90d, DB password 180d.
- **Touches**: `application.yml`, deployment config, ops docs.
- **Effort**: 1–2 days + infra.

### 2.3 Structured plaintext encoding for vault entries
- **Problem**: `"${title}|${username}|${password}|..."` (`mobile/app/src/androidMain/kotlin/com/securevault/mobile/data/local/AndroidEntryEncryptor.kt:44`) — any `|` in a field corrupts the entry on decrypt.
- **Fix**: Encrypt a **JSON-serialized** entry with a versioned schema (`{"v":1,"title":...,"username":...}`). Add a `schema_version` field to support future evolution.
- **Touches**: `EntryEncryptor` (both platforms), `VaultEntry` shape on client.
- **Effort**: half a day. Migration: read both old `|`-format and new JSON until backfill complete.

### 2.4 Certificate pinning on mobile
- **Problem**: A rogue CA or user-installed root CA can MitM TLS. Vault payloads are encrypted, but auth tokens are exposed.
- **Fix**:
  - Pin the production server's leaf or intermediate certificate via Ktor's `CertificatePinner` (Android) and `URLSession` pinning (iOS).
  - Pin **two certs** (current + next) so rotation doesn't brick clients.
  - Provide a kill-switch config endpoint to disable pinning in emergencies (signed config, not user-toggleable).
- **Touches**: Ktor client config, iOS network layer, deployment runbook.
- **Effort**: 2 days.

### 2.5 Per-account login lockout in addition to per-IP rate limit
- **Problem**: Current 5-attempt lockout is per-account, but rate limit is per-IP. Distributed brute force across IPs against one account isn't covered by IP limits.
- **Fix**: Already partially addressed — verify the per-account lockout in `AuthService.handleFailedLogin` works under concurrent attempts (use DB row-level lock or atomic counter), and add **CAPTCHA** challenge after 3 failures.
- **Effort**: 1 day.

### 2.6 Audit log hardening
- **Problem**: `AuditLog` stores raw IP (GDPR concern), no integrity protection.
- **Fix**:
  - Hash IPs with a daily-rotating HMAC key (still queryable for "same IP today" without storing PII long-term).
  - Append-only constraint at DB level (revoke UPDATE/DELETE on the table from app role).
  - Optional: chain audit entries with `prev_hash` for tamper-evidence.
  - Define a retention policy (e.g. 90 days for security events, 30 days for benign events).
- **Touches**: `AuditService`, `AuditLog` entity, DB grants, retention job.
- **Effort**: 2 days.

---

## Phase 3 — Defense in depth (weeks 7–10)

### 3.1 Argon2id parameter tuning + storage
- Bump server Argon2id memory to **96MB** (closer to 1Password's 100MB).
- Store params per-user (`kdf_iterations`, `kdf_memory`) so you can upgrade without breaking old accounts.
- Background re-hash on next login when params change.
- **Effort**: 1.5 days.

### 3.2 Optional "secret key" (1Password-style)
- 128-bit random value generated at signup, **never sent to the server**.
- Combined with master password for KDF input.
- Defends against weak master passwords — even a leaked DB + brute-forced master password is useless without the secret key.
- Tradeoff: account recovery becomes near-impossible (which is the point).
- **Effort**: 4–5 days, including UX flows for "show secret key", "print recovery sheet", "device-to-device transfer".

### 3.3 Security headers + CSP
- Add **Content-Security-Policy** (relevant if Swagger UI or any browser-served pages exist).
- `Referrer-Policy: no-referrer`, `Permissions-Policy`, `X-Content-Type-Options: nosniff`.
- Make Swagger UI **disabled by default in prod** (already configurable via `SWAGGER_ENABLED` — verify default is `false`).
- **Effort**: half a day.

### 3.4 Replay protection on sensitive endpoints
- For `/auth/change-password`, `/2fa/disable`, `/vault DELETE all`: require a fresh authentication challenge (re-enter master password within the request) — sometimes called **sudo mode**.
- Issue a 5-minute "elevated" token that gates these endpoints.
- **Effort**: 2 days.

### 3.5 Device binding & session management
- Already have a `Device` entity — wire it up:
  - On login, register the device fingerprint (UA + a stable client-generated ID stored in Keystore).
  - List active sessions per user; allow revoke-per-device.
  - Notify user (email) on new device login.
- **Effort**: 3 days.

### 3.6 Encrypted database backups
- Document and automate: `pg_dump` → encrypt with a separate KMS key → store in S3 with object lock.
- Restore drills quarterly.
- **Effort**: 1 day + infra.

### 3.7 Dependency & supply chain
- Add **Dependabot / Renovate** for automated dep updates.
- Add **OWASP Dependency-Check** or **Snyk** to CI; fail builds on CVSS ≥ 7.
- Pin Maven Central via checksums; consider **sigstore** verification for critical deps.
- **Effort**: 1 day.

### 3.8 Static analysis & secret scanning
- Add **Semgrep** or **CodeQL** to CI with a security-focused ruleset.
- Add **gitleaks** as a pre-commit hook + CI check.
- **Effort**: half a day.

---

## Phase 4 — Operational maturity (ongoing)

| Item | Why |
|---|---|
| **Penetration test** by a third party before GA | Independent verification; catches what reviewers miss |
| **Bug bounty program** (HackerOne / Intigriti) | Continuous external scrutiny |
| **SOC 2 Type II** roadmap if B2B | Required by enterprise customers |
| **Incident response runbook** | Pre-defined steps for token leak, DB compromise, key rotation under duress |
| **Security training** for contributors | Most vulnerabilities come from well-meaning code |
| **Threat model document** kept in repo | Forces explicit reasoning about new features |
| **Quarterly key-rotation drills** | Verify rotation actually works before you need it |
| **Monitoring & alerting**: failed logins, lockouts, 429s, JWT validation failures, unusual vault access patterns | Detect attacks in progress |
| **Signed releases** (mobile) | Prevents APK swap attacks |
| **Reproducible builds** (mobile) | Lets users verify the binary matches source |

---

## Suggested execution order

```
Week 1     : Phase 0 (DEK rewrap, 2FA enforcement, KDF upgrade)   ← BLOCKING
Week 2-3   : Phase 1 (refresh hashing, rate limits, breach check, token revocation, mobile mem)
Week 4-6   : Phase 2 (JWT rotation, secret manager, JSON encoding, cert pinning, audit hardening)
Week 7-10  : Phase 3 (Argon2 tuning, secret key, headers, sudo mode, device binding)
Ongoing    : Phase 4 (pen test, bug bounty, monitoring, drills)
```

**Total effort estimate to reach industry-standard**: ~10 engineer-weeks for a single experienced developer, or ~5–6 weeks with a pair. After Phase 2 you're at "shippable to security-conscious users." After Phase 3 you're competitive with Bitwarden's security posture (not feature parity — just security).
