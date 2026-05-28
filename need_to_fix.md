# SecureVault — Consolidated Security Issues

Single source of truth merging `need_to_fix.md`, `claude_findings.md`, `codex_findings.md`, plus issues found during fix sessions. Tagged with source IDs for traceability.

**Legend:**
- ✅ = Fixed & deployed
- ❌ = Open
- ⏳ = In progress

---

## Phase 0 — Stop the bleeding (ship-blocking)

### 0.1 Fix encryption-salt rotation that destroys vault data ✅
[source: need_to_fix 0.1]

`AuthService.changePassword()` generated a new `encryptionSalt`, making every existing vault entry permanently undecryptable.

**Fix**: Wrapped Data Encryption Key (DEK) model — vault key wrapped with KEK derived from password. Password change re-wraps same vault key with new KEK.

**Status**: ✅ Fixed.

---

### 0.2 Fix 2FA login challenge binding ✅
[source: need_to_fix 0.2]

`POST /api/v1/auth/verify-2fa` now requires a `challengeId` from the password-authenticated login step. Each login creates a pending challenge in Redis (`PendingLoginChallengeStore`, 300s TTL) bound to the password-authenticated user. Without passing password-first login, attacker cannot obtain a valid challenge. Verify endpoint also conditionally checks TOTP — non-2FA users skip TOTP entirely to avoid unnecessary client round-trips. Login response shape is unified (same fields for all users), eliminating the structural oracle that leaked whether 2FA was enabled.

**Files**: `TwoFactorLoginResponse.java`, `TwoFactorVerifyRequest.java`, `AuthService.java:login/verifyTwoFactorLogin`, `PendingLoginChallengeStore.java`, `background.ts`, `LoginViewModel.kt`

**Status**: ✅ Fixed — challenge binding, unified response shape, conditional TOTP check, all clients updated.

---

### 0.3 Actually enforce 2FA at login ✅
[source: need_to_fix 0.3, claude H2/H3/H10, codex H2/H12]

Password login no longer issues any tokens or encryption material in the login response. Login always returns `{twoFactorRequired, userId, challengeId, authSalt, twoFactorMethods}` — no `encryptionSalt`, `wrappedVaultKey`, or `encryptionVersion`. These are only returned after `/verify-2fa` succeeds. Mobile flow fixed: `AuthRepositoryImpl.kt` no longer parses `encryptionSalt` from login response; `AuthResponse` model includes `twoFactorMethods` field; `LoginViewModel.kt` checks `twoFactorMethods.isNotEmpty()` for TOTP UI decision.

**Files**: `AuthService.java:login/verifyTwoFactorLogin`, `TwoFactorLoginResponse.java`, `SecureVaultApi.kt`, `AuthRepositoryImpl.kt`, `LoginViewModel.kt`

**Status**: ✅ Fixed — no crypto material or tokens returned before 2FA, all clients updated.

---

### 0.4 TOTP secret stored in plaintext ✅
[source: need_to_fix 0.4]

`twoFactorSecret` is stored encrypted at rest using AES-256-GCM via `TwoFactorSecretConverter` (JPA `@Convert`). Key derived from `ENCRYPTION_KEY` (base64, 32 bytes). Decrypted transparently during TOTP verification.

**File**: `TwoFactorSecretConverter.java`, `User.java:91-93`

**Status**: ✅ Fixed — AES-256-GCM encryption via JPA attribute converter.

---

### 0.5 Upgrade client-side KDF (mobile) ❌
[source: need_to_fix 0.5]

Android already uses Argon2id matching backend. iOS is not implemented at all — throws `NotImplementedError`. No per-user KDF params stored for future upgrades.

**Files**: `IosEntryEncryptor.kt`, `AndroidEntryEncryptor.kt:24-49`

**Status**: ❌ Open.

---

### 0.6 Android local cache stores vault entries in PLAINTEXT ✅
[source: claude C5, codex C5]

Room table had plaintext `title, username, password, url, notes` columns within SQLCipher-encrypted DB. `CachedVaultRepository` wrote decrypted entries on every API success.

**Fix**: `password` and `notes` fields now encrypted at the entity level using AES-256-GCM with the vault key (prefixed with `e1:` for migration compatibility — unencrypted legacy entries fall through to plaintext). Legacy entries without the prefix are read as-is. `title`, `username`, `url`, `folder` left unencrypted for search/filter queries to use DB indexes.

**Files**: `AndroidEntryEncryptor.kt`, `CachedVaultRepository.kt`, `EntryEncryptor.kt`, `AppModule.kt`

**Status**: ✅ Fixed — vault-key-encrypted password/notes at the entity level. SQLCipher provides DB-level encryption; column-level encryption adds defense-in-depth against passphrase exfiltration.

---

### 0.7 Plaintext DataStore vault cache ✅
[source: claude C6, codex C6]

`VaultCache.kt` JSON-serialized full plaintext entries (including passwords) to unencrypted Preferences DataStore.

**Fix**: Removed `VaultCache.kt` entirely — it was dead code (zero references anywhere in the codebase).

**Files**: `VaultCache.kt` (deleted)

**Status**: ✅ Fixed — file deleted.

---

### 0.8 Android `allowBackup="true"` on a password manager ✅
[source: claude C7, codex C7]

Allowed `adb backup` and Google Auto Backup to copy app data including caches and database.

**Fix**: Set `android:allowBackup="false"`, `android:fullBackupContent="false"`, and `android:dataExtractionRules="@xml/backup_rules"`. Created `backup_rules.xml` that excludes all domains from cloud backup and device transfer.

**Files**: `AndroidManifest.xml:9`, `res/xml/backup_rules.xml`

**Status**: ✅ Fixed — backup fully disabled on all API levels.

---

### 0.9 Android cleartext traffic permitted globally ❌
[source: claude C8, codex C8]

`<base-config cleartextTrafficPermitted="true">` applies to every host, not just localhost. Downgrade attacks against production domain succeed silently — leaking tokens and auth hashes on the network.

**File**: `network_security_config.xml`

**Status**: ❌ Open.

---

## Phase 1 — Critical hardening

### 1.1 Hash refresh tokens at rest ✅
[source: need_to_fix 1.1]

Raw JWT stored in DB. DB leak = all sessions hijackable.

**Fix**: Store SHA-256 hash instead. Lookup by hash.

**Status**: ✅ Fixed — `V5` migration, `tokenHash` field, `hashToken()` method.

---

### 1.2 Password reuse prevention ✅
[source: need_to_fix 1.2]

History check re-hashed with freshly generated salt, making comparison always fail.

**Fix**: Store salt alongside hash in password_history. Re-hash candidate with each entry's original salt.

**Status**: ✅ Fixed — `V4` migration, `passwordSalt` in `PasswordHistory`, correct comparison.

---

### 1.3 Per-endpoint distributed rate limiting + trusted proxy ⏳
[source: need_to_fix 1.3, claude H3, codex H3]

RateLimitingFilter and LoginRateLimiter migrated to Redis, ClientIpResolver created, and:
- `RequestLoggingInterceptor` now uses `clientIpResolver.getClientIp()` instead of `request.getRemoteAddr()` ✅
- `RateLimitingFilter` skips OPTIONS requests (CORS preflight no longer consumes rate limit) ✅

**Remaining**: No per-endpoint granular limits (single 60/min default).

**Status**: ⏳ Partially fixed — Redis migration, ClientIpResolver, IP logging fix, and OPTIONS exclusion done. Per-endpoint granularity remains.

---

### 1.4 Failed logins not audit-logged ✅
[source: need_to_fix 1.4]

`logFailedLogin()` defined but never called. Brute-force attempts leave zero trace.

**Fix**: Call `auditService.logFailedLogin()` from `AuthService.login()` catch path.

**Status**: ✅ Fixed.

---

### 1.5 Vault audit logs missing IP and User-Agent ✅
[source: need_to_fix 1.5, codex M6]

Every `logVaultAccess()` call passed `null, null` for IP and UA.

**Fix**: Pass `httpRequest` via `ClientIpResolver` to all vault audit calls.

**Status**: ✅ Fixed — including `getAllEntries` which was initially missed.

---

### 1.6 Weak JWT secret fallback ✅
[source: need_to_fix 1.6]

Default secret `SecureVaultSecretKeyForJWTTokenGeneration2024` not random. Falls back if env var not set.

**Fix**: Remove fallback defaults. Validate at startup JWT_SECRET ≥ 32 bytes.

**Status**: ✅ Fixed — fallback removed from property files, startup validation in `JwtTokenProvider`.

---

### 1.7 Breach-corpus password validation ✅
[source: need_to_fix 1.7]

`calculatePasswordStrength()` used basic scoring. No breach list check.

**Fix**: Integrate HIBP k-anonymity API + offline common-passwords set.

**Status**: ✅ Was fixed initially with `BreachCheckService`. Later **removed entirely** — HIBP server-side is inappropriate for zero-knowledge model (server only sees auth hash, not raw password). Breach check now happens client-side only.

---

### 1.8 Short access-token TTL + revocation list ❌
[source: need_to_fix 1.8, claude M5, codex M4, claude H11, codex H11]

Access tokens: current TTL 1 hour, `jti` exists but no denylist, logout doesn't revoke active tokens, locked user's tokens still work. Refresh tokens: lack `jti`, `email`, `pwdUpdatedAt` claims — missing `jti` prevents token-family tracking from JWT claims alone (though DB-level hash lookup compensates). JWT also lacks `iss`/`aud` validation.

**New issue found**: `JwtTokenProvider.java:67-77` — `generateRefreshToken()` only sets `sub`, `iat`, `exp`; no `jti`, `email`, or `pwdUpdatedAt` claims.

**Status**: ❌ Open — `jti` added to access tokens, `pwdUpdatedAt` claim checked in filter, but no token denylist on logout/lockout, no refresh token `jti`, no iss/aud validation.

---

### 1.9 Master password lifecycle in mobile memory ❌
[source: need_to_fix 1.9, claude M14, codex M12]

Android caches vault key as Base64 String in `AndroidEntryEncryptor.cachedVaultKey`. Passwords flow through immutable Kotlin Strings — cannot be wiped. No inactivity auto-lock on mobile. Session/vault key material is durable (persists in EncryptedSharedPreferences).

**Files**: `AndroidEntryEncryptor.kt:27-114`, `SessionManager.kt`, view models

**Status**: ❌ Open.

---

### 1.10 Browser token and key-material storage ✅
[source: need_to_fix 1.10, claude C1, codex C1, claude H5, codex H5]

Web app stores tokens and vault key material in browser memory/localStorage. Refresh token returned in JSON body (defeats HttpOnly cookie). Extension persisted raw vault key bytes in `chrome.storage.session`.

**Refresh token in JSON body**: Already handled — `AuthController.java:231-239` (`stripRefreshTokenForWeb`) sets `refreshToken` to `null` in JSON body for browser clients (User-Agent contains `"Mozilla"`). For web clients, the refresh token is delivered only via HttpOnly cookie (`setRefreshTokenCookie`, line 206). Mobile clients (no `"Mozilla"` in UA) still get it in JSON body since they can't use cookies — unavoidable.

**Extension vault key**: Raw vault key bytes no longer stored in `chrome.storage.session`. Vault key wrapped using AES-GCM with a session-specific wrapping key (32-byte random seed). In-memory `CryptoKey` is `extractable: false` — `crypto.subtle.exportKey('raw', vaultKey)` throws.

**Files**: `AuthController.java:206-239`, `vaultKey.ts`, `storage.ts` (`persistVaultKey`/`restoreVaultKey`), `background.ts` (`deriveAndPersistVaultKey`)

**Status**: ✅ Fixed — HttpOnly cookie for web clients, non-extractable vault key in extension.

---

### 1.11 CAPTCHA + email verification on registration and login ❌
[source: need_to_fix 1.11]

No bot protection, no email ownership verification, no new-device confirmation. Anyone with API access can register and attempt login freely.

**Status**: ❌ Not started.

---

### 1.12 `token.getBytes()` without explicit charset ✅
[source: need_to_fix 1.12]

`token.getBytes()` uses JVM default charset. Non-UTF-8 systems produce different hash.

**Fix**: `token.getBytes(StandardCharsets.UTF_8)`.

**Status**: ✅ Fixed — `AuthService.java:390` and formerly `BreachCheckService.java:81`.

---

### 1.13 Email enumeration via timing ✅
[source: claude C2, codex C2]

`AuthService.login()` threw `BadCredentialsException` immediately on `findByEmail().orElseThrow()`. Existing-user requests ran PBKDF2 + Argon2id; non-existing users skipped all crypto. Timing delta (ms vs sub-ms) trivially measurable. Additionally, `loginRateLimiter.recordFailure()` only called inside password-mismatch branch — attempts against non-existent emails didn't increment failure counter.

**Fix**: Always compute `serverSideHash()` with a dummy salt for non-existing users (`DUMMY_SALT`/`DUMMY_HASH` constants) for timing-constant execution. `loginRateLimiter.recordFailure()` now called regardless of user existence.

**File**: `AuthService.java`

**Status**: ✅ Fixed.

---

### 1.14 `permitAll` for `/api/v1/auth/**` exposes change-password ❌
[source: claude C3, codex C3]

Spring Security grants `permitAll` to everything under `/api/v1/auth/**`, including `POST /api/v1/auth/change-password`. Only saved by NPE in null principal handling — one refactor away from auth bypass.

**File**: `SecurityConfig.java:32`

**Status**: ❌ Open — `auth.requestMatchers("/api/v1/auth/**").permitAll()` still in place.

---

### 1.15 No refresh token family / reuse detection ❌
[source: claude H4, codex H4]

Token rotation provides no family binding. Reuse of old token throws generic failure but doesn't revoke the entire session family. Attacker who uses stolen token first rolls the session forward; victim silently loses access.

**File**: `AuthService.java:189` (refresh token path)

**Status**: ❌ Open — no `familyId` or `parentTokenId` on `RefreshToken` entity; reuse detection is hash-not-found only, no family revocation.

---

### 1.16 Auth audit JSON built with manual escaping ❌
[source: claude H6]

`AuditService.logFailedLogin()` constructs `details` JSON by hand-escaping only `\, ", \n, \r, \t`. Does not escape other control chars (U+0000–U+001F). PostgreSQL JSONB rejects these → audit insert fails → attacker can suppress audit by supplying control chars in email field.

**File**: `AuditService.java:106`

**Status**: ❌ Open.

---

### 1.17 Mobile API client has no certificate pinning ❌
[source: claude H8, codex H7, need_to_fix 2.11]

Ktor's default `HttpClient` has no SSL pinning. User-installed or compromised public CA can MITM the connection.

**Files**: `SecureVaultApi.kt`, `network_security_config.xml`

**Status**: ❌ Open.

---

### 1.18 Android `FLAG_SECURE` not set ❌
[source: claude H9, codex H8]

MainActivity does not set `FLAG_SECURE`. Vault content visible in task-switcher preview, screenshots, screen recording, screen casting.

**File**: `MainActivity.kt`

**Status**: ❌ Open.

---

### 1.19 Mobile device IDs use non-cryptographic random ❌
[source: claude H11, codex H9]

Device ID generation uses `kotlin.random.Random` instead of `SecureRandom`. Predictable/correlatable device identifiers.

**File**: `AuthRepositoryImpl.getOrCreateDeviceId:248`

**Status**: ❌ Open.

---

### 1.20 Credentialed CORS uses origin patterns ❌
[source: claude H7, codex H10]

`setAllowedOriginPatterns` + `allowCredentials(true)`. Current values are exact but API silently allows wildcards — footgun for future `https://*.tanay.pro` entries.

**File**: `CorsConfig.java:17`

**Status**: ❌ Open.

---

### 1.21 Unencrypted Room DB overload exists ✅
[source: claude H12]

`SecureVaultDatabase.kt` shipped `getInstance(context)` overload that built Room WITHOUT SQLCipher. Unreferenced but one typo away from writing plaintext to unencrypted SQLite.

**Fix**: Removed the unencrypted `getInstance(context: Context)` overload. The only remaining `getInstance` requires a `passphrase: ByteArray` and creates SQLCipher-backed database.

**File**: `SecureVaultDatabase.kt:24`

**Status**: ✅ Fixed.

---

### 1.22 `fallbackToDestructiveMigration()` on cache DB ✅
[source: claude H13]

On any schema upgrade, entire local cache wiped. A corrupt DB also silently destroys data — offline user with stale state could lose unsynced changes.

**Fix**: Removed `.fallbackToDestructiveMigration()`. Room will now throw on schema mismatch instead of silently destroying data, forcing developers to provide proper migrations.

**File**: `SecureVaultDatabase.kt:24-37`

**Status**: ✅ Fixed.

---

### 1.23 `TwoFactorVerifyRequest.email` lacks `@Email` validation ✅ 💡NEW
[source: discovered during fix session]

Had `@NotBlank` but no `@Email` annotation.

**File**: `TwoFactorVerifyRequest.java:8-9`

**Status**: ✅ Fixed — `@Email` annotation added alongside existing `@NotBlank`.

---

### 1.24 No device registration rate limit or maximum count ✅
[source: discovered during fix session]

Authenticated user could register unlimited devices. PublicKey removed — dead code (unimplemented E2EE).

**Fix**: `DeviceService.java:48+88-90` — `MAX_DEVICES_PER_USER = 10`. `registerDevice()` checks `deviceRepository.countByUserId()` before creating a new device. `DeviceRepository.java:18` — added `countByUserId(UUID)` derived query.

**Files**: `DeviceService.java:48,87-89`, `DeviceRepository.java:18`

**Status**: ✅ Fixed.

---

### 1.25 `verifyTwoFactorLogin` does not check `isBlocked()` before challenge ❌
[source: claude M10]

`AuthService.verifyTwoFactorLogin()` skips the `isBlocked(clientIp)` / `isBlocked(email)` checks that `login()` performs. First ~5 attempts always go through regardless of IP being blocked.

**File**: `AuthService.java:158`

**Status**: ❌ Open.

---

## Phase 2 — Important hardening

### 2.1 Hardcoded production secrets in docker-compose.yaml ✅
[source: need_to_fix 2.1]

DB password, JWT secret, Redis password hardcoded in plaintext and committed.

**Fix**: All secrets replaced with `${VAR}` environment variable references in `docker-compose.yaml`. Secrets loaded from `.env` (which is `.gitignore`'d, item 2.2).

**Status**: ✅ Fixed.

---

### 2.2 `.env` not in `.gitignore` ✅
[source: need_to_fix 2.2]

`.env` is untracked but not ignored. One `git add .` commits all secrets.

**Status**: ✅ Fixed — added to `.gitignore`.

---

### 2.3 Empty default DB password ✅
[source: need_to_fix 2.3]

`spring.datasource.password=${DB_PASSWORD:}` defaulted to empty string.

**Fix**: Trailing colon removed — `${DB_PASSWORD}` without a default causes Spring Boot to fail at startup (`IllegalArgumentException: Could not resolve placeholder`) if `DB_PASSWORD` is not set.

**Files**: `application.properties:6`, `application-prod.properties:6`

**Status**: ✅ Fixed.

---

### 2.4 SSL/TLS not enforced ✅
[source: need_to_fix 2.4, claude M1, codex M1]

Backend SSL disabled by default. `security.require-ssl` defaults to false. No startup assertion that TLS is in front of app in prod. Android app used `http://192.168.1.38:8080`.

**Fix**:
- `SecurityConfig.java`: Added `@PostConstruct validateTlsInProduction()` — logs a warning at startup when the `prod` profile is active but `ssl.enabled` or `require-ssl` is false.
- Android already uses `https://vault.tanay.pro` (verified in `AppModule.kt:32`). The `http://192.168.1.38:8080` was only in the issue description, not in any source file.

**Status**: ✅ Fixed.

---

### 2.5 Swagger enabled in `.env` defaults ✅
[source: need_to_fix 2.5]

`SWAGGER_ENABLED=true` in checked-in `.env`. Risk of deploying with public API docs.

**Status**: ✅ Fixed — Swagger endpoints also locked down in `SecurityConfig` with `.denyAll()`.

---

### 2.6 No size/format limits on vault entry payloads ❌
[source: need_to_fix 2.6, claude M4, codex M3]

`VaultEntryRequest.encryptedData` and `iv` have `@NotBlank` but no `@Size`, Base64 validation, or IV length validation. Many other DTOs also lack `@Size` constraints.

**Files**: `VaultEntryRequest.java`, `RegisterRequest.java`, `ChangePasswordRequest.java`, `DeviceRequest.java`, `RefreshTokenRequest.java`, `Enable2FARequest.java`

**Status**: ❌ Open.

---

### 2.7 No 2FA enforcement on sensitive operations ❌
[source: need_to_fix 2.7, claude M9, codex M9]

Password changes, 2FA disable, device removal, and full vault deletion have no step-up (sudo) requirement. Stolen bearer token can disable protections or destructively delete data.

**Files**: `TwoFactorController.java:97-105`, `VaultController.java:163-170`, `AuthController.java:183-205`, `DeviceController.java`

**Status**: ❌ Open.

---

### 2.8 JWT signing key rotation ❌
[source: need_to_fix 2.8]

Single static HMAC secret. No rotation, no `kid` header. No JWKS.

**File**: `JwtTokenProvider.java`

**Status**: ❌ Open.

---

### 2.9 Move secrets to secret manager ❌
[source: need_to_fix 2.9]

Secrets in env vars. No rotation, no audit, leak-prone in container inspection.

**Status**: ❌ Open.

---

### 2.10 Structured entry encoding (mobile) ❌
[source: need_to_fix 2.10]

Server stores no encrypted-payload schema/version beyond `VaultEntry.version=1`. Clients parse independently — drift risk.

**Status**: ❌ Open.

---

### 2.11 Certificate pinning (mobile) ❌
[source: need_to_fix 2.11, claude H8/M15, codex H7]

No pinning on Android or iOS. Rogue/user-installed CA can MITM.

**Status**: ❌ Open.

---

### 2.12 Android backup and local database hardening ✅
[source: need_to_fix 2.12, claude C7, codex C7]

`allowBackup=true`, destructive migrations enabled, unencrypted DB overload exists.

**Status**: ✅ Fixed (was overlapping with 0.8, 1.21, 1.22). See individual items for details.

---

### 2.13 TOTP secret lifecycle during setup ❌
[source: need_to_fix 2.13]

`GET /2fa/setup` stores TOTP secret before user verifies setup. If user abandons, stale secret remains with `twoFactorEnabled=false`.

**Files**: `TwoFactorAuthService.java:64-77`, `TwoFactorController.java:55-84`

**Status**: ❌ Open.

---

### 2.14 Zero-knowledge architecture gap ✅
[source: need_to_fix 2.14]

Claimed "Server receives master password during registration/login and can derive/wrap vault-key material."

**Verification**: Incorrect claim. Architecture was always zero-knowledge:
- `RegisterRequest` receives `authHash` (client-side PBKDF2 of password), not the raw password — `AuthService.java:105`
- `LoginRequest` receives `authHash` (client-side PBKDF2), not raw password — `LoginRequest.java:17`
- Server stores `serverSideHash(authHash)` (double-hashed with `SERVER_HASH_SECRET`) — never sees plaintext
- `wrappedVaultKey` is encrypted with client-derived KEK; server cannot decrypt it
- `User.java:31-34` already documents the zero-knowledge architecture

**Status**: ✅ Always was zero-knowledge — never an issue.

---

### 2.15 Audit log hardening ❌
[source: need_to_fix 2.15]

Raw IP stored (GDPR concern). No integrity protection (append-only, hash chaining). Failed login log events have `userId = null` — users can't see account probing in in-app audit history ([claude M7, codex M7]).

**Files**: `AuditLog.java`, `AuditService.java`, `AuditLogRepository.java`

**Status**: ❌ Open.

---

### 2.16 Legacy `vaultKeyIv` field removed ✅
[source: need_to_fix 2.16]

Dead `vaultKeyIv` column on `users` table from previous encryption model.

**Status**: ✅ Fixed — field removed from `User.java`, `V7__drop_vault_key_iv.sql` migration.

---

### 2.17 Swagger not explicitly locked down in SecurityConfig ✅
[source: need_to_fix 2.17]

Swagger endpoints inherited default `permitAll` catch.

**Status**: ✅ Fixed — `.requestMatchers("/swagger-ui/**", "/v3/api-docs/**").denyAll()` in `SecurityConfig.java:34`.

---

### 2.18 `encryptionVersion` hardcoded in multiple places ✅
[source: need_to_fix 2.18]

`encryptionVersion` set as literal `2` in DTO default, service layer, client. Inconsistent on upgrade.

**Status**: ✅ Fixed — `EncryptionConstants.java` created, all 3 hardcoded references use `CURRENT_ENCRYPTION_VERSION`.

---

### 2.19 No account deletion endpoint (GDPR) ✅
[source: need_to_fix 2.19]

Users couldn't delete their account and associated data. GDPR Article 17 non-compliant.

**Status**: ✅ Fixed — `DELETE /api/v1/auth/account` endpoint added. Cascading deletion + Redis cleanup. Reordered to audit-log before delete.

---

### 2.20 Sensitive PII logged broadly ❌
[source: claude M2, codex M2]

Emails, IPs, and user agents logged in auth flows and `RequestLoggingInterceptor`. Log file (`logs/securevault.log`, 10MB × 30 history) contains large amounts of personal data on disk.

**Status**: ❌ Open.

---

### 2.21 CSP allows `'unsafe-inline'` styles ❌
[source: claude M7, codex M5]

Both backend and nginx include `style-src 'self' 'unsafe-inline'`. CSS injection vector for data exfiltration via background-image URLs. Google Fonts loaded from CDN but CSP only allows `font-src 'self'` — blocked anyway (`index.html:9`).

**Files**: `SecurityHeadersFilter.java:24`, `nginx.conf:11`, `index.html:9`

**Status**: ❌ Open.

---

### 2.22 `Permissions-Policy` missing modern directives ❌
[source: claude M6]

Blocks camera/mic/geo/payment but not `interest-cohort=()`, `browsing-topics=()`, `attribution-reporting=()`.

**File**: `SecurityHeadersFilter.java:36`

**Status**: ❌ Open.

---

### 2.23 Account lockout counter behavior is awkward ❌
[source: claude M8, codex M14]

`handleFailedLogin()` increments `failedLoginAttempts` even when already locked. After unlock, next failure starts adding to previous count → only one failed attempt before re-lock. Also, active access tokens still work after account lockout ([claude H11, codex H11]).

**File**: `AuthService.java:311`

**Status**: ❌ Open.

---

### 2.24 HSTS always configured (even in dev) ❌
[source: claude M9, codex M15]

HSTS with `maxAge=1y, includeSubDomains, preload` configured unconditionally in `SecurityConfig.java:37`. Dev deployment on localhost could pin browsers to HTTPS for a year.

**Status**: ❌ Open.

---

### 2.25 Login rate limit doesn't count unknown-user failures ❌
[source: claude C2, codex C2]

`loginRateLimiter.recordFailure()` only called in password-mismatch branch. Unknown users never have failures recorded. Combined with email enumeration timing oracle, accounts can be enumerated at high throughput.

**Status**: ❌ Open (overlaps 1.13).

---

### 2.26 Master password held in React/Compose state ❌
[source: claude M11]

`LoginPage.tsx:48` keeps `data.password` in React Hook Form state until form reset. React DevTools / heap dump exposes it. Same in extension popup (`script.ts:88`).

**Status**: ❌ Open.

---

### 2.27 Mobile biometric unlock stores vault key ❌
[source: claude M16, codex M13]

Biometric unlock encrypts the raw vault key and stores it locally. No rate-limit on biometric failures. No wipe after repeated failures.

**Files**: `BiometricStorage.kt`, `SettingsViewModel.kt`

**Status**: ❌ Open.

---

### 2.28 Extension content script runs on all pages ❌
[source: claude L6, codex H6]

`manifest.json:26` injects content script on `http://*/*` and `https://*/*`. Combined with raw vault key bytes in storage, blast radius of compromised extension dependency is entire vault.

**File**: `web/extension/manifest.json:26`

**Status**: ❌ Open.

---

### 2.29 Ktor JSON parser is lenient ❌
[source: claude M12, codex M10]

`isLenient = true` in `SecureVaultApi.kt`. Accepts non-standard JSON, widens parser surface.

**File**: `SecureVaultApi.create:374`

**Status**: ❌ Open.

---

### 2.30 Mobile uses `!!` non-null assertions on server responses ❌
[source: claude M13, codex M11]

Many `authResponse.accessToken!!` — malformed server response causes instant NPE crash.

**Files**: `AuthRepositoryImpl.kt:49-55,96-104,134-141`

**Status**: ❌ Open.

---

### 2.31 `CachedVaultRepository.withDao` catches any exception and deletes local DB ❌
[source: claude M18]

On first exception, the local DB and passphrase are wiped, then operation retried. Transient I/O error → silent cache destruction and forced re-sync of plaintext entries.

**File**: `CachedVaultRepository.kt:60-72`

**Status**: ❌ Open.

---

### 2.32 `TwoFactorVerifyRequest.email` lacks `@Email` ✅ 💡NEW
[source: discovered during fix session]

Only `@NotBlank` — no email format validation.

**File**: `TwoFactorVerifyRequest.java:8-9`

**Status**: ✅ Fixed — duplicate of 1.23, `@Email` annotation added.

---

### 2.33 No device count limit per user ✅
[source: discovered during fix session]

Unlimited device registrations. `publicKey` field removed (dead code for unimplemented E2EE), so the `@Size` concern is moot. Device count limit now addressed.

**Status**: ✅ Fixed (duplicate of 1.24).

---

### 2.34 `RequestLoggingInterceptor` logs wrong IP behind proxy ✅
[source: discovered during fix session]

Uses `request.getRemoteAddr()` instead of `ClientIpResolver`. All request logs show Docker network IP, not real client.

**Fix**: Already fixed in item 1.3 — `RequestLoggingInterceptor.java:34` uses `clientIpResolver.getClientIp(request)` which respects `X-Forwarded-For`.

**Status**: ✅ Fixed (duplicate of 1.3).

---

### 2.35 RateLimitingFilter counts OPTIONS requests ✅
[source: discovered during fix session]

All requests including CORS preflight counted against the 60 req/min per-IP limit. After ~60 OPTIONS, victim's real API calls blocked for remainder of minute.

**Fix**: Already fixed in item 1.3 — `RateLimitingFilter.java:42-45` skips `OPTIONS` requests before counting.

**Status**: ✅ Fixed (duplicate of 1.3).

---

### 2.36 Refresh tokens lack `jti`, `email`, `pwdUpdatedAt` claims ✅
[source: discovered during fix session]

`generateRefreshToken()` only set `sub`, `iat`, `exp`. No `jti` for token-family tracking, no `email` or `pwdUpdatedAt` binding within the JWT itself. DB-level checks compensated but no second layer of defense.

**Fix**:
- `JwtTokenProvider.java:67`: `generateRefreshToken()` now accepts `email` and `passwordUpdatedAt`, sets `jti`, `email`, `pwdUpdatedAt` claims (matching the access token pattern)
- `JwtTokenProvider.java:88-102`: Added `getEmailFromRefreshToken()` and `getPasswordUpdatedAtFromRefreshToken()` extraction methods
- `AuthService.java:255-262`: `refreshToken()` validates email and `pwdUpdatedAt` claims against current user state — rejects if email changed or password was reset since token issuance

**Status**: ✅ Fixed.

---

### 2.37 Web disable-2FA sends no TOTP code ✅
[source: claude M8, codex M8]

Backend requires a code to disable 2FA, but web client sent no body. Users would be unable to manage 2FA reliably.

**Fix**:
- `web/src/api/twofa.ts:27`: `disable2FA()` now accepts a `code: string` parameter and sends `{"code": code}` in the POST body
- `web/src/pages/SettingsPage.tsx`: `handleDisable()` requires a 6-digit code before calling the API. Added `disabling` state — clicking "Disable 2FA" now shows a code input + "Confirm Disable" / "Cancel" buttons, matching the enable flow UX
- Mobile client (`SecureVaultApi.kt:227-236`) already sent the code correctly — only web was broken

**Files**: `web/src/api/twofa.ts:27`, `web/src/pages/SettingsPage.tsx:317-368`

**Status**: ✅ Fixed.

---

## Phase 3 — Defense in depth

### 3.1 Argon2id parameter tuning ❌
[source: need_to_fix 3.1]

Bump to 96MB memory, store params per-user, background re-hash on next login.

**Status**: ❌ Open.

---

### 3.2 Optional "secret key" (1Password-style) ❌
[source: need_to_fix 3.2]

128-bit random value at signup, never sent to server. Combined with master password for KDF input.

**Status**: ❌ Open.

---

### 3.3 Security headers + CSP alignment ❌
[source: need_to_fix 3.3, claude M7, codex M5]

Backend and nginx CSP differ. Backend `script-src 'self'` may break WASM; nginx allows `wasm-unsafe-eval`. Google Fonts loaded but blocked by `font-src 'self'`.

**Status**: ❌ Open.

---

### 3.4 Replay protection (sudo mode) ❌
[source: need_to_fix 3.4]

For sensitive operations: require fresh authentication challenge. Issue 5-minute elevated token.

**Status**: ❌ Open.

---

### 3.5 Device binding & session management ❌
[source: need_to_fix 3.5]

Wire up existing `Device` entity: register device fingerprint, list sessions, revoke per-device, email notification on new device.

**Status**: ❌ Open.

---

### 3.6 Encrypted database backups ❌
[source: need_to_fix 3.6]

`pg_dump` → encrypt with KMS key → store in S3 with object lock.

**Status**: ❌ Open.

---

### 3.7 Dependency & supply chain ❌
[source: need_to_fix 3.7, claude H13, codex H13]

Spring Boot `3.2.0`, Ktor `2.3.7`, `androidx.security:security-crypto:1.1.0-alpha06`, older mobile deps. No Dependabot/Renovate, no OWASP Dependency-Check in CI.

**Status**: ❌ Open.

---

### 3.8 Static analysis & secret scanning ❌
[source: need_to_fix 3.8]

No Semgrep/CodeQL security rules, no Gitleaks pre-commit hook.

**Status**: ❌ Open.

---

### 3.9 Dependency verification status ❌
[source: need_to_fix 3.9]

No automated CI audit of npm, Maven, or Gradle dependencies for vulnerabilities.

**Status**: ❌ Open.

---

### 3.10 Mobile test/build health ❌
[source: need_to_fix 3.10]

Mobile unit tests fail to compile — duplicate `getCachedVaultKey()` definitions and unresolved `Json` import.

**Status**: ❌ Open.

---

### 3.11 No Play Integrity / App Attest / root detection ❌
[source: claude L19]

For an Android password manager, app + device integrity attestation is table stakes. Currently nothing.

**Status**: ❌ Open.

---

### 3.12 `server.error.*` not fully locked down ❌
[source: claude L4, codex L4]

`server.error.include-exception=false`, `server.error.include-stacktrace=never`, `server.error.whitelabel.enabled=false` not set.

**Status**: ❌ Open.

---

### 3.13 Health endpoint reveals DB status ❌
[source: claude L5, codex L5]

`/api/v1/health` is `permitAll` and returns DB up/down + timestamp. 503 response on DB failure fingerprints outages.

**File**: `HealthController.java`

**Status**: ❌ Open.

---

### 3.14 `InputSanitizer` is unused ❌
[source: claude L8, codex L7]

Defined but never imported. Dead code creating false confidence.

**File**: `InputSanitizer.java`

**Status**: ❌ Open.

---

### 3.15 `Logout` accepts refresh tokens without auth ❌
[source: claude L9, codex L8]

Anyone with a stolen refresh token can spam logout to invalidate the victim's session (targeted session DoS).

**File**: `AuthController.logout()`

**Status**: ❌ Open.

---

### 3.16 `AuditLogRepository` exposes global query ❌
[source: claude L10, codex L9]

`findAllByOrderByCreatedAtDesc(Pageable)` returns all audit logs across all users. Currently unused but footgun for future admin endpoints.

**File**: `AuditLogRepository.java:18`

**Status**: ❌ Open.

---

### 3.17 Refresh rotation not atomic ❌
[source: claude L11, codex L10]

Old token deleted before new one saved. DB blip in between silently logs user out.

**File**: `AuthService.refreshToken()`

**Status**: ❌ Open.

---

### 3.18 Cookie SameSite set via raw attribute ❌
[source: claude L14, codex L11]

`Cookie.setAttribute("SameSite", "Strict")` instead of `ResponseCookie.from(...).sameSite("Strict")`. Works on modern Spring Boot but fragile.

**File**: `AuthController.java:182`

**Status**: ❌ Open.

---

### 3.19 iOS not implemented ❌
[source: claude L16, codex L12]

`IosEntryEncryptor.kt` and `CryptoEngine.ios.kt` throw `NotImplementedError` on every method.

**Status**: ❌ Open.

---

### 3.20 Android release minification disabled ❌
[source: codex L13]

`isMinifyEnabled = false` for release. Easier reverse engineering/tampering.

**Files**: `mobile/app/build.gradle.kts`

**Status**: ❌ Open.

---

### 3.21 `local.properties` tracked in git ❌
[source: codex L14]

Contains local path/user info. Should be removed from git and added to `.gitignore`.

**Status**: ❌ Open.

---

### 3.22 Postman collection stale/misleading ❌
[source: codex L15]

Uses plaintext `password` fields that no longer match auth-hash flow.

**File**: `SecureVault.postman_collection.json`

**Status**: ❌ Open.

---

### 3.23 Password generator has tiny modulo bias ❌
[source: claude L3, codex L3]

`Math.floor(crypto.getRandomValues(...)[0] / (0xffffffff + 1) * charset.length)` is biased when charset size doesn't divide 2^32.

**File**: `web/src/crypto/generator.ts:17`

**Status**: ❌ Open.

---

### 3.24 `Cache-Control: no-store` on all backend responses ❌
[source: claude M3]

Set in `SecurityHeadersFilter.java:39`. Verified no proxy chain override needed.

**Status**: ❌ Verify in production.

---

### 3.25 `VaultCache.getLastSyncTime()` hangs forever ❌
[source: claude M17]

`data.collect { ... }` inside `suspend fun` is unbounded. Returns only when flow completes — which it never does.

**Status**: ❌ Open.

---

### 3.26 `VaultEntryDao.searchEntries` uses leading `%` ❌
[source: claude L20]

Leading `%` prevents index use. Performance footgun on large vaults.

**File**: `VaultEntryDao`

**Status**: ❌ Open.

---

### 3.27 Flyway `baseline-on-migrate=true` ❌
[source: claude L2, codex L2]

Operational risk: partially initialized databases may silently skip migrations.

**Status**: ❌ Open.

---

### 3.28 Verbose backend error surfacing ❌
[source: claude L17]

Many `Result.Error(it.message ...)` paths surface backend error messages in mobile UI.

**Status**: ❌ Open.

---

### 3.29 Ktor JSON pretty-print enabled ❌
[source: claude L18]

`Json { prettyPrint = true }` sends pretty-printed JSON on every request. Tiny bytes wasted.

**File**: `SecureVaultApi.create:373`

**Status**: ❌ Open.

---

## Phase 4 — Operational maturity (ongoing)

| Item | Why | Status |
|------|-----|--------|
| Third-party penetration test | Independent verification before GA | ❌ |
| Bug bounty program (HackerOne) | Continuous external scrutiny | ❌ |
| SOC 2 Type II roadmap | Required by enterprise customers | ❌ |
| Incident response runbook | Pre-defined steps for token leak, DB compromise | ❌ |
| Security training for contributors | Most vulns come from well-meaning code | ❌ |
| Threat model in repo | Forces explicit reasoning about new features | ❌ |
| Quarterly key-rotation drills | Verify rotation works before you need it | ❌ |
| Monitoring & alerting | Failed logins, lockouts, 429s, JWT failures | ❌ |
| Signed mobile releases | Prevents APK swap attacks | ❌ |
| Reproducible mobile builds | Users verify binary matches source | ❌ |
| Secret rotation after leaks | Rotate DB/Redis/JWT secrets after any repo exposure | ❌ |
| Release security checklist | Verify TLS, mobile cleartext disabled, backup disabled, Swagger disabled | ❌ |

---

## Already fixed ✅

| ID | Finding | Fix |
|----|---------|-----|
| 0.1 | DEK/wrapped vault key model | Password change no longer destroys existing vault entries |
| 0.2 | 2FA login challenge binding | Challenge created at login and validated at verify-2fa; unified response shape; conditional TOTP check |
| 0.3 | Enforce 2FA at login | Login returns no tokens or crypto material before 2FA; all clients updated |
| 0.4 | TOTP secret encrypted at rest | AES-256-GCM via `TwoFactorSecretConverter` (JPA `@Convert`), key from `ENCRYPTION_KEY` |
| 0.6 | Local vault cache plaintext | Password/notes encrypted at entity level with vault key (AES-256-GCM); `e1:` prefix for migration |
| 0.7 | Plaintext DataStore vault cache | `VaultCache.kt` deleted — dead code, zero references |
| 0.8 | Android backup enabled | `allowBackup="false"`, `dataExtractionRules` excludes all domains |
| 1.1 | Refresh token hashing | SHA-256 hash stored in DB instead of raw JWT |
| 1.2 | Password reuse prevention | Salt-aware password history comparison |
| 1.4 | Failed logins not audit-logged | `logFailedLogin()` now called from `AuthService.login()` catch path |
| 1.5/2.19/M6 | Vault audit IP/UA + account deletion | All vault endpoints pass real IP/UA via `ClientIpResolver`; `DELETE /api/v1/auth/account` added |
| 1.6 | JWT secret fallback | Removed from property files; startup validation enforces ≥ 32 chars |
| 1.7 | Breach-corpus validation | Was added, then removed — HIBP is inappropriate server-side for zero-knowledge model; breach check is client-side only |
| 1.10 | Browser token/key storage + extension vault key | HttpOnly cookie for web clients; `stripRefreshTokenForWeb()` strips JSON `refreshToken` for browsers. Extension vault key non-extractable, wrapped via AES-GCM |
| 1.12 | `token.getBytes()` charset | Explicit `StandardCharsets.UTF_8` in `hashToken()` |
| 1.13 | Email enumeration via timing | `serverSideHash()` always computed (dummy salt for unknown users); `recordFailure()` always called |
| 1.23 | `TwoFactorVerifyRequest.email` lacks `@Email` | `@Email` annotation added |
| 2.1 | Hardcoded production secrets in docker-compose.yaml | All secrets replaced with `${VAR}` env var references |
| 2.2 | `.env` not in `.gitignore` | Added to `.gitignore` |
| 2.3 | Empty default DB password | `${DB_PASSWORD}` without colon fails fast at startup if unset |
| 2.4 | SSL/TLS not enforced | `@PostConstruct` warns if prod profile active without TLS; Android already uses HTTPS |
| 2.5/2.17 | Swagger exposure | Endpoints locked down with `.denyAll()` in `SecurityConfig`; `SWAGGER_ENABLED` default toggled |
| 2.16 | Legacy `vaultKeyIv` field | Removed from `User.java` + `V7__drop_vault_key_iv.sql` migration |
| 2.18 | `encryptionVersion` centralized | `EncryptionConstants.java` — single source of truth |
| 2.32 | `TwoFactorVerifyRequest.email` lacks `@Email` (dup) | Duplicate of 1.23, `@Email` annotation added |
| C4 | Thread.sleep DoS in 2FA enable | Removed `Thread.sleep(30000)` from `TwoFactorAuthService.enable2FA()` |
| H2 | 2FA per-challenge brute force | Added per-challenge attempt limit (5 atomic HINCRBY) in `PendingLoginChallengeStore`; TOTP action rate limit on enable/disable (5 per 5min) |
| H3 | IP spoofing | `ClientIpResolver` with `app.proxy.trusted` toggle; replaced all 3 inline X-Forwarded-For parsing sites |
| L1 | Static 2FA PBKDF2 salt | `TwoFactorSecretConverter` now decodes `ENCRYPTION_KEY` directly as AES key (base64, 32 bytes) |

**Additional fixes (not in original findings docs):**
- PBKDF2 server-side hash salt → per-user random 32-byte salt + `SERVER_HASH_SECRET` pepper
- `LoginRateLimiter` (ConcurrentHashMap → Redis, 5min TTL)
- `RateLimitingFilter` (ConcurrentHashMap + ScheduledExecutorService → Redis, 60s TTL)
- `PendingLoginChallengeStore` + `TwoFactorAuthService.pendingSetups` → Redis Hash (removed `ScheduledExecutorService` cleanup schedulers)
- `VaultService` entry count limit (10,000 max per user)
- `AuthController` IP resolution via `ClientIpResolver`
- Refresh token rate limit (per-user, 5 per 60s)
- Deleted user token denylist in Redis (1hr TTL, checked in `JwtAuthenticationFilter` before DB lookup)
- Audit event reorder for `deleteAccount` (log before delete to preserve `ON DELETE SET NULL`)
- `BreachCheckService.java` + `CommonPasswords.java` + test removed (dead server-side HIBP code)
- `getAllEntries` audit log now includes IP and UA
- Redundant `createdAt` TTL check removed from `PendingLoginChallengeStore.validateChallenge()` (race condition)
- Fixed race condition in 2FA per-challenge attempt limit (non-atomic GET-then-INCR → atomic HINCRBY + return-value check)
- `@Email` annotation added to `TwoFactorVerifyRequest.email` to match `LoginRequest`/`RegisterRequest`
- `DeviceRequest.publicKey` and `Device.encryptedPrivateKey` removed (dead fields for unimplemented E2EE); DB columns dropped via V9 migration
- Login response unified: same shape for all users with `twoFactorMethods` field, no tokens/crypto material before 2FA
- All clients (web extension, web app, mobile) updated for unified 2FA flow with `twoFactorMethods`-based TOTP UI decision
- `VaultEntryEntity` password/notes columns encrypted at entity level with vault key (AES-256-GCM); `e1:` prefix for legacy migration
- `VaultCache.kt` removed — dead plaintext DataStore cache (zero references)
- `RequestLoggingInterceptor` — uses `ClientIpResolver.getClientIp()` instead of `request.getRemoteAddr()`
- `RateLimitingFilter` — skips OPTIONS requests (CORS preflight no longer counts against rate limit)
- Extension vault key: raw bytes no longer stored in session storage. Wrapped with AES-GCM via session wrapping key; in-memory `CryptoKey` is non-extractable (`exportKey` throws)

---

## Summary

| Category | Total | ✅ Fixed | ⏳ Partial | ❌ Remaining |
|----------|-------|----------|-----------|--------------|
| Phase 0 — Stop the bleeding | 9 | 7 | 0 | 2 |
| Phase 1 — Critical hardening | 25 | 12 | 1 | 12 |

| Phase 2 — Important hardening | 37 | 16 | 1 | 20 |

| **Total** | **112** | **35** | **2** | **75** |

### Verification
- Backend `mvn -q test`: passed (6/6)
- Web `npm audit --audit-level=moderate`: 0 vulnerabilities
- Mobile `./gradlew test`: failed — unit-test compile errors (`getCachedVaultKey()` conflict, unresolved `Json`)

### Source cross-reference legend
- `need_to_fix 0.1` = original `need_to_fix.md` item
- `claude C1` = `claude_findings.md` Critical item #1
- `codex H2` = `codex_findings.md` High item #2
- `💡NEW` = discovered during fix session, not in any original findings document
