# SecureVault - Security Review: Need to Fix

Review date: May 15, 2026
Scope: All Java/Spring Boot backend source, configs, DB migrations, Docker/deploy files

---

## 🔴 CRITICAL

### 1. Hardcoded production secrets in docker-compose.yaml

**File**: `docker-compose.yaml:17-21`

DB password (`mg8Jn^#Cpe`), JWT secret, and Redis password are hardcoded in plaintext and committed to git. Anyone with repo access gets all production secrets.

**Fix**: Use environment variables or a `.env` file referenced by Docker Compose. Remove secrets from version control.

---

### 2. 2FA setup is completely broken

**Files**: `TwoFactorController.java:82`, `TwoFactorAuthService.java:111-121`

`enable2FA()` is called with `secret=null`. The `verifyCode()` check always fails because the stored TOTP secret is null at setup time. `Enable2FARequest` has no `secret` field — the generated secret from the setup endpoint is never passed back to the enable endpoint. 2FA can never be enabled by any user.

**Fix**: 
- Add a `secret` field to `Enable2FARequest`
- Pass the generated secret from the setup response to `enable2FA()`
- Fix `enable2FA()` to verify the code against the provided secret instead of the stored (null) secret

---

### 3. Password reuse prevention is non-functional

**File**: `AuthService.java:256-262`

The history check re-hashes the new password with a freshly generated `newAuthSalt` inside the comparison loop, then compares against old hashes (which were created with different salts). The comparison always fails — users can reuse their last password immediately.

**Fix**: Re-hash using each historical entry's original salt, or compute the new hash once outside the loop and compare against stored hashes.

---

## 🔴 HIGH

### 4. Refresh tokens stored in plaintext

**File**: `RefreshToken.java:48-49`

JWT refresh tokens are stored as-is in the database. DB compromise = all active sessions can be hijacked.

**Fix**: Store a SHA-256 hash of the token instead of the raw JWT. Validate incoming refresh tokens by hashing first, then looking up the hash.

---

### 5. TOTP 2FA secret stored in plaintext

**File**: `User.java:80-81`

`twoFactorSecret` is stored unencrypted in the database. If the DB is breached, attackers can generate valid TOTP codes for any user.

**Fix**: Encrypt the TOTP secret at rest using AES-256-GCM with a server-side key. Decrypt only when verifying codes.

---

### 6. Failed logins are never audit-logged

**File**: `AuthController.java:88-101`

`auditService.logFailedLogin()` exists but is never called. When login fails, the exception propagates to `GlobalExceptionHandler` and no audit record is created. Brute-force attacks leave no trace in the audit log.

**Fix**: Call `auditService.logFailedLogin()` in the `AuthService.login()` catch path or in the controller before the exception propagates.

---

### 7. Weak/guessable default JWT secret

**Files**: `.env:11`, `application.properties:20`

The secret `SecureVaultSecretKeyForJWTTokenGeneration2024` is not cryptographically random. Both `application.properties` and `application-prod.properties` fall back to this same string if the environment variable is not set.

**Fix**: 
- Remove fallback defaults from properties files (require `JWT_SECRET` to be set)
- Generate secrets using `openssl rand -base64 32` as documented in `.env.example`
- Validate at startup that the secret is at least 32 bytes

---

### 8. No 2FA enforcement on sensitive operations

**Scope**: All controllers

Once a user logs in, password changes, device registration, and vault access have no 2FA re-verification. If a JWT is stolen, 2FA (if it could be enabled) provides no protection.

**Fix**: Require TOTP re-verification for sensitive operations (password change, disable 2FA, new device registration).

---

## 🟡 MEDIUM

### 9. In-memory rate limiting — resets on restart

**Files**: `LoginRateLimiter.java`, `RateLimitingFilter.java`

Both rate limiters use in-memory `ConcurrentHashMap`. On server restart, all rate limit state is lost. Attackers can trigger a restart then brute-force.

**Fix**: Use Redis (already in the dependency stack) or another persistent store for rate limit state. The existing Redis dependency makes this straightforward.

---

### 10. X-Forwarded-For spoofing bypasses rate limiting

**File**: `RateLimitingFilter.java:53-58`

The rate limiter trusts the `X-Forwarded-For` header without validation. An attacker can spoof IPs to bypass per-IP rate limits.

**Fix**: Only trust `X-Forwarded-For` when the request comes from a known reverse proxy. Alternatively, combine IP with a device fingerprint or use a proxy trust strategy.

---

### 11. No size limits on vault entry payloads

**File**: `VaultEntryRequest.java`

`encryptedData` and `iv` fields have no `@Size` constraint. An attacker could store arbitrarily large blobs, leading to storage exhaustion.

**Fix**: Add `@Size(max = ...)` constraints on both fields (e.g., 64KB for encrypted data, reasonable limit for IV).

---

### 12. Missing CSRF protection rationale

**File**: `SecurityConfig.java:30`

CSRF is disabled. While acceptable for JWT/bearer-token-based APIs, there is no comment explaining why.

**Fix**: Add a comment explaining that CSRF is disabled because the API uses JWT bearer tokens (not cookies) for authentication.

---

### 13. SSL/TLS not enforced in production config

**Files**: `application-prod.properties:34`, `.env:17`

`REQUIRE_SSL=false` and `server.ssl.enabled=${SSL_ENABLED:false}`. Credentials and encrypted vault data travel in plaintext without transport encryption unless a reverse proxy handles TLS.

**Fix**: 
- Set `REQUIRE_SSL=true` in `.env.example` as the documented production expectation
- Ensure the reverse proxy (Traefik in docker-compose) enforces HTTPS
- Consider using Spring Boot's built-in SSL for direct deployments

---

### 14. Swagger enabled in `.env` defaults

**File**: `.env:18`

`SWAGGER_ENABLED=true`. If deployed without overriding this env var, the full API surface is publicly documented and explorable.

**Fix**: Set `SWAGGER_ENABLED=false` in `.env`. Only enable it in development profiles.

---

### 15. Empty default DB password

**File**: `application.properties:6`

`spring.datasource.password=${DB_PASSWORD:}` — defaults to empty string if the env var is not set. Also affects `application-prod.properties`.

**Fix**: Remove the empty default or add a startup check that fails if `DB_PASSWORD` is not set.

---

### 16. Password change lacks rate limiting

**File**: `AuthController.java:163`

The `/change-password` endpoint has no rate limiting. A compromised JWT allows unlimited current-password guessing.

**Fix**: Apply rate limiting to the change-password endpoint, keyed by user ID.

---

### 17. JWT has no early revocation mechanism

**File**: `JwtTokenProvider.java`

Leaked tokens stay valid until expiration (1 hour default). No blacklist or revocation list exists.

**Fix**: Consider maintaining an in-memory or Redis-based token blacklist for immediate revocation capability, or keep access token lifetimes short (already 15 min default).

---

## 🔵 LOW

### 18. Email logged in audit on failed login

**File**: `AuditService.java:107`

Failed login emails are stored in audit JSON. Acceptable for security monitoring, but should be reviewed against data retention policy.

**Consideration**: Implement audit log rotation/purging, or hash email addresses in failed-login records after a retention period.

---

### 19. Health endpoint leaks DB status

**File**: `HealthController.java:56-57`

Returns `database: UP/DOWN`. Minor information disclosure.

**Consideration**: Restrict health endpoint to internal networks only, or remove the database status field.

---

### 20. UserUtils.getUserId() fallback is broken

**File**: `UserUtils.java:14`

Falls back to `UUID.fromString(userDetails.getUsername())` which tries to parse an email as UUID — will throw an exception.

**Consideration**: Remove the fallback or make it a safe no-op. Currently unreachable with the existing `CustomUserDetails` usage, but fragile.

---

### 21. Logging interceptor could leak sensitive data

**File**: `RequestLoggingInterceptor.java:25-30`

Currently logs method, URI, IP, and User-Agent. If future changes add header logging, `Authorization` headers could leak.

**Consideration**: Add a comment warning against logging `Authorization` header.

---

### 22. Server listens on all interfaces

**File**: `application.properties:28`

`server.address=0.0.0.0` — fine when behind a reverse proxy, but risky if accidentally exposed directly.

**Consideration**: Bind to `127.0.0.1` in development, require explicit override for `0.0.0.0` in production behind proxy.
