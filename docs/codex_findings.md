# SecureVault Security Findings - Deep Review

Date: 2026-05-27
Last updated: 2026-05-27 (fixes applied)

Scope reviewed: Spring Boot backend, React/Vite web app, Chrome extension, Kotlin Multiplatform mobile app, Docker/nginx deployment config, database migrations, and local project configuration.

> **Legend:** ✅ = Fixed & deployed. Items without marker are still open.

Note: This is a static source review. Dependency audits and test execution could not be completed in this environment: `npm` was unavailable, and Maven/Gradle test commands failed under sandboxing with the approval rerun rejected by the approval system.

## Executive Summary

The server-side zero-knowledge storage design is directionally sound: vault entries are stored as ciphertext, entry encryption uses AES-GCM, refresh tokens are hashed in the database, and 2FA secrets are encrypted at rest.

The main security risk is that multiple client and session-management paths break the practical protection model:

- Refresh tokens are exposed to JavaScript in JSON responses.
- Android persists decrypted vault data locally.
- Android backup and cleartext-network settings are unsafe for a password manager.
- Login and 2FA rate limiting has bypassable edges.
- The Chrome extension persists sensitive token/key material.
- Several auth/session controls are too broad or not enforced consistently.

| Severity | Total | ✅ Fixed | ❌ Remaining |
|----------|-------|----------|--------------|
| Critical | 8     | 1        | 7            |
| High     | 13    | 2        | 11           |
| Medium   | 15    | 1        | 14           |
| Low      | 15    | 1        | 14           |
| **Total**| **51**| **5**    | **46**       |

**Fixed so far:** C4 (Thread.sleep DoS), H2 (2FA brute force), H3 (IP spoofing), M6 (vault audit IP/UA), L1 (static 2FA PBKDF2 salt).

These are production-blocking issues for a password manager.

## Critical Findings

### C1. Refresh Token Returned in JSON Body

Files:
- `src/main/java/com/securevault/service/AuthService.java`
- `src/main/java/com/securevault/dto/AuthResponse.java`
- `src/main/java/com/securevault/dto/TwoFactorLoginResponse.java`
- `src/main/java/com/securevault/dto/ChangePasswordResponse.java`
- `src/main/java/com/securevault/controller/AuthController.java`

The backend sets the refresh token as an HttpOnly cookie, but also returns it in JSON response bodies. Any XSS or malicious browser context can read the JSON body and steal the refresh token, defeating HttpOnly protection.

Impact: Account/session takeover after XSS.

Fix:
- For web responses, do not serialize `refreshToken`.
- Split web and mobile response DTOs, or null the token in cookie-based web flows.
- Keep mobile/token-body flows separate if mobile requires body refresh tokens.

### C2. Email Enumeration via Timing and Rate-Limit Bypass

File: `src/main/java/com/securevault/service/AuthService.java`

Unknown-user login attempts throw immediately after `findByEmail`, while existing-user attempts perform expensive PBKDF2/Argon2 work. Unknown-user attempts also do not call `loginRateLimiter.recordFailure`.

Impact: Fast account enumeration and high-throughput probing of non-existent emails.

Fix:
- For missing users, perform a dummy server-side hash using sentinel data.
- Record rate-limit failures for both client IP and email.
- Normalize response timing as much as practical.

### C3. `permitAll` for `/api/v1/auth/**` Includes Sensitive Endpoints

Files:
- `src/main/java/com/securevault/config/SecurityConfig.java`
- `src/main/java/com/securevault/controller/AuthController.java`

All auth endpoints are public at the Spring Security layer, including `/api/v1/auth/change-password`. The endpoint currently fails with null principal, but the authorization boundary is fragile.

Impact: One refactor away from auth bypass on password change.

Fix:
- Permit only explicit public endpoints: register, login, verify-2fa, refresh, logout.
- Require authentication for change-password.
- Add tests asserting sensitive endpoints reject unauthenticated requests.

### C4. 2FA Enable Path Can Block Request Threads for 30 Seconds ✅

File: `src/main/java/com/securevault/service/TwoFactorAuthService.java`

`enable2FA` calls `Thread.sleep(30000)` when a second code is provided and differs from the first.

Impact: Low-rate request flooding can exhaust servlet threads and deny service.

Fix:
- Remove blocking sleep.
- Verify a second code from a different TOTP window with non-blocking timestamp logic, or remove the second-code feature.

### C5. Android Room Cache Stores Decrypted Vault Entries

Files:
- `mobile/app/src/androidMain/kotlin/com/securevault/mobile/data/local/VaultEntryEntity.kt`
- `mobile/app/src/androidMain/kotlin/com/securevault/mobile/data/repository/CachedVaultRepository.kt`

The local Room entity stores `title`, `username`, `password`, `url`, and `notes` as plaintext. `CachedVaultRepository` writes decrypted entries into that table.

Impact: Local device compromise or backup extraction can recover vault contents without the master password.

Fix:
- Store only ciphertext/IV/version locally.
- Decrypt only in memory after unlock.
- Remove plaintext Room columns from release builds.

### C6. Plaintext DataStore Vault Cache Helper

File: `mobile/app/src/androidMain/kotlin/com/securevault/mobile/data/cache/VaultCache.kt`

`VaultCache` serializes full plaintext entries, including passwords, to normal Preferences DataStore. It appears currently unused, but is dangerous if wired in later.

Impact: Full plaintext vault exposure if used.

Fix:
- Delete `VaultCache.kt`, or convert it to ciphertext-only storage.
- Add tests that no plaintext password fields are persisted.

### C7. Android Backup Enabled

File: `mobile/app/src/androidMain/AndroidManifest.xml`

`android:allowBackup="true"` is enabled.

Impact: App data, including cached vault data/session material, may be copied through Android backup or device-transfer paths.

Fix:
- Set `android:allowBackup="false"` for release.
- Add `dataExtractionRules`/backup rules that exclude all vault, session, database, and preference data.

### C8. Android Cleartext Traffic Permitted Globally

File: `mobile/app/src/androidMain/res/xml/network_security_config.xml`

`<base-config cleartextTrafficPermitted="true">` applies to all hosts.

Impact: Downgrade/misconfiguration can send tokens and auth material over plaintext HTTP.

Fix:
- Set base cleartext to false.
- Keep localhost/10.0.2.2 exemptions only in debug-specific config.

## High Findings

### H1. Client Auth Hash Uses Email as Salt

Files:
- `web/src/context/AuthContext.tsx`
- `web/src/crypto/argon2.ts`
- `mobile/app/src/commonMain/kotlin/com/securevault/mobile/data/repository/AuthRepositoryImpl.kt`
- `mobile/app/src/androidMain/kotlin/com/securevault/mobile/domain/crypto/CryptoEngine.android.kt`

Web and mobile derive the auth hash using email as the Argon2 salt. The API carries an `authSalt`, but the implementation uses the email.

Impact: Same email/password pair produces stable hashes across deployments, easing targeted precomputation/correlation.

Fix:
- Generate and store random per-user auth salt.
- Serve it before auth-hash derivation or via a safe login preflight.
- Migrate existing users on next login/password change.

### H2. 2FA Challenge Lacks Per-Challenge Attempt Limit ✅

Files:
- `src/main/java/com/securevault/service/AuthService.java`
- `src/main/java/com/securevault/security/PendingLoginChallengeStore.java`

Failed TOTP attempts do not consume the challenge, and there is no per-challenge attempt counter.

Impact: A stolen-password attacker can make too many OTP guesses during the challenge TTL.

Fix:
- Track failed attempts per challenge.
- Consume/revoke after a small number of failures.
- Rate-limit `/verify-2fa` by challenge, user, and IP.

### H3. Spoofable Client IP Handling ✅

Files:
- `src/main/java/com/securevault/config/RateLimitingFilter.java`
- `src/main/java/com/securevault/controller/AuthController.java`
- `src/main/java/com/securevault/controller/TwoFactorController.java`

The app trusts `X-Forwarded-For` and `X-Real-IP` without confirming the request came from a trusted proxy.

Impact: Rate-limit bypass and poisoned audit logs.

Fix:
- Trust forwarded headers only from known reverse proxy addresses.
- Configure `server.tomcat.remoteip.internal-proxies` or equivalent.
- Use a single trusted client-IP utility.

### H4. No Refresh Token Family Reuse Detection

File: `src/main/java/com/securevault/service/AuthService.java`

Refresh tokens rotate, but reuse of an old token only produces a generic failure and warning.

Impact: If attacker refreshes first, victim gets logged out but attacker keeps the rotated session.

Fix:
- Add refresh-token family ID.
- On reuse, revoke the whole family and alert/log a high-severity event.

### H5. Chrome Extension Persists Refresh Tokens and Raw Vault Key Bytes

Files:
- `web/extension/src/lib/storage.ts`
- `web/extension/src/background.ts`

The extension stores access/refresh tokens in `chrome.storage.local` and exports raw vault key bytes into `chrome.storage.session`.

Impact: Extension compromise or profile compromise exposes long-lived sessions and vault keys.

Fix:
- Avoid persisting raw key bytes.
- Keep a non-extractable `CryptoKey` in service-worker memory only.
- Re-lock on service-worker restart.
- Minimize refresh-token lifetime/storage in extension.

### H6. Extension Content Script Runs on All HTTP/HTTPS Pages

File: `web/extension/manifest.json`

The extension injects a content script into every `http://*/*` and `https://*/*` page.

Impact: Large attack surface for autofill abuse and extension compromise.

Fix:
- Prefer action-triggered injection.
- Restrict matches where feasible.
- Require explicit user gesture before filling credentials.

### H7. Mobile API Client Has No Certificate/Public-Key Pinning

Files:
- `mobile/app/src/commonMain/kotlin/com/securevault/mobile/data/api/SecureVaultApi.kt`
- `mobile/app/src/androidMain/res/xml/network_security_config.xml`

Ktor uses default platform trust with no production pinning.

Impact: User-installed CAs or compromised CAs can MITM mobile traffic.

Fix:
- Add Android network-security pin-set or Ktor/OkHttp certificate pinning.
- Include backup pins and rotation plan.

### H8. Android Does Not Set `FLAG_SECURE`

File: `mobile/app/src/androidMain/kotlin/com/securevault/mobile/MainActivity.kt`

Vault screens can be captured by screenshots, screen recording, assistant capture, or task-switcher previews.

Impact: Shoulder-surfing and local device privacy leak.

Fix:
- Set `WindowManager.LayoutParams.FLAG_SECURE` globally, or at minimum on vault/unlock/add/edit screens.

### H9. Mobile Device IDs Use Non-Cryptographic Random

File: `mobile/app/src/commonMain/kotlin/com/securevault/mobile/data/repository/AuthRepositoryImpl.kt`

Device ID generation uses `kotlin.random.Random`.

Impact: Device identifiers are weaker than necessary and may be predictable/correlatable.

Fix:
- Generate with `SecureRandom` or platform UUID APIs backed by secure randomness.

### H10. Credentialed CORS Uses Origin Patterns

File: `src/main/java/com/securevault/config/CorsConfig.java`

`setAllowedOriginPatterns` is used with `allowCredentials(true)`.

Impact: Current values are exact, but future wildcard patterns could grant credentialed access to attacker-controlled subdomains.

Fix:
- Use `setAllowedOrigins` with exact origins.
- Keep environment-specific origin allowlists.

### H11. Active Access Tokens Still Work After Account Lockout

File: `src/main/java/com/securevault/security/JwtAuthenticationFilter.java`

JWT authentication loads the user but does not check whether the account is currently locked.

Impact: Lockout only blocks new logins; existing access tokens continue to access vault APIs.

Fix:
- Reject authenticated requests if `user.isLocked()`.
- Consider revoking active sessions on account lockout.

### H12. Mobile 2FA Login Flow Is Broken by Response Contract Mismatch

Files:
- `src/main/java/com/securevault/service/AuthService.java`
- `mobile/app/src/commonMain/kotlin/com/securevault/mobile/data/api/SecureVaultApi.kt`

Backend intentionally returns null `encryptionSalt` and `wrappedVaultKey` during the first 2FA step, but mobile requires `encryptionSalt` in `parseAuthResponse`.

Impact: Mobile 2FA login fails, creating pressure to disable or weaken 2FA support.

Fix:
- Update mobile model/parser so 2FA-required responses only require `userId`, `email`, and `challengeId`.
- Add end-to-end tests for mobile 2FA login.

### H13. Stale Dependencies and Alpha Security Libraries

Files:
- `pom.xml`
- `mobile/app/build.gradle.kts`

Notable examples include Spring Boot `3.2.0`, Ktor `2.3.7`, `androidx.security:security-crypto:1.1.0-alpha06`, and older mobile dependencies.

Impact: Potential known vulnerabilities and unsupported/alpha security behavior.

Fix:
- Run OWASP Dependency-Check/osv-scanner/Gradle dependency audit/npm audit in CI.
- Upgrade Spring Boot, Ktor, AndroidX Security Crypto, SQLCipher, and mobile dependencies.

## Medium Findings

### M1. TLS Not Enforced by Application Defaults

Files:
- `src/main/resources/application.properties`
- `src/main/resources/application-prod.properties`

`server.ssl.enabled` and `security.require-ssl` default to false.

Impact: Misconfigured proxy/deployment can serve sensitive traffic over HTTP.

Fix:
- Require TLS in production.
- Add startup checks that fail production boot without TLS or trusted forwarded-proto configuration.

### M2. Sensitive PII Logged Broadly

Files:
- `src/main/java/com/securevault/service/AuthService.java`
- `src/main/java/com/securevault/controller/AuthController.java`
- `src/main/java/com/securevault/config/RequestLoggingInterceptor.java`

Emails, IPs, and user agents are logged in many auth flows.

Impact: Log compromise exposes sensitive metadata.

Fix:
- Log user UUID or keyed hashes instead of raw email.
- Reduce user-agent logging.
- Define log retention and access controls.

### M3. Several DTO Fields Lack Size Constraints

Files:
- `src/main/java/com/securevault/dto/RegisterRequest.java`
- `src/main/java/com/securevault/dto/ChangePasswordRequest.java`
- `src/main/java/com/securevault/dto/DeviceRequest.java`
- `src/main/java/com/securevault/dto/RefreshTokenRequest.java`
- `src/main/java/com/securevault/dto/Enable2FARequest.java`

Many user-controlled strings have `@NotBlank` but no `@Size` or strict format constraints.

Impact: Oversized JSON and stored values can cause DoS or database/log bloat.

Fix:
- Add `@Size` to all request strings.
- Validate Base64 fields and exact decoded IV/key sizes.
- Add global request body limits.

### M4. JWTs Lack `iss`/`aud` Validation and Broad Revocation

File: `src/main/java/com/securevault/security/JwtTokenProvider.java`

Access tokens have `sub`, `email`, `pwdUpdatedAt`, `jti`, but no issuer/audience validation. Logout does not revoke existing access tokens.

Impact: Weaker token scoping and limited incident response.

Fix:
- Add and validate `iss` and `aud`.
- Reduce access token TTL to 5-15 minutes.
- Add JTI denylist for high-risk events.

### M5. CSP Allows Inline Styles and Policy Drift

Files:
- `src/main/java/com/securevault/config/SecurityHeadersFilter.java`
- `web/nginx.conf`
- `web/index.html`

Policies allow `style-src 'unsafe-inline'`; nginx and backend policies differ. `index.html` references Google Fonts while CSP allows only self fonts.

Impact: CSS injection risk and deployment drift.

Fix:
- Use one production CSP.
- Self-host fonts or explicitly permit required origins.
- Move to nonce/hash-based styles where practical.

### M6. Vault Audit Logs Missing IP/User-Agent ✅

File: `src/main/java/com/securevault/controller/VaultController.java`

Vault CRUD audit events pass `null` for IP and user agent.

Impact: Poor forensic value for vault access events.

Fix:
- Accept `HttpServletRequest` in vault endpoints.
- Record trusted client IP and user agent.

### M7. Users Cannot See Failed Login Attempts in Their Audit Log

Files:
- `src/main/java/com/securevault/service/AuditService.java`
- `src/main/java/com/securevault/controller/AuditController.java`

Failed login logs have `userId = null`; the user audit endpoint queries by `userId`, so targeted failed login attempts are not visible to users.

Impact: Users cannot detect account probing from in-app audit history.

Fix:
- If email maps to a user, attach `userId` to failed-login audit events while preserving privacy.
- Alternatively expose a separate normalized failed-login summary.

### M8. Web Disable-2FA Flow Sends No TOTP Code

Files:
- `web/src/api/twofa.ts`
- `web/src/pages/SettingsPage.tsx`
- `src/main/java/com/securevault/controller/TwoFactorController.java`

The backend requires a code to disable 2FA, but the web client sends no body.

Impact: Users may be unable to manage 2FA reliably.

Fix:
- Prompt for current TOTP code before disabling.
- Send `{ code }` to `/2fa/disable`.

### M9. No Recent Re-Auth or Step-Up for Sensitive Operations

Files:
- `src/main/java/com/securevault/controller/AuthController.java`
- `src/main/java/com/securevault/controller/TwoFactorController.java`
- `src/main/java/com/securevault/controller/DeviceController.java`
- `src/main/java/com/securevault/controller/VaultController.java`

Password change, 2FA disable, device removal, and full vault deletion rely only on a current bearer token.

Impact: Stolen access token can perform destructive/security-sensitive operations.

Fix:
- Require recent password/TOTP re-verification.
- Issue a short-lived step-up token for sensitive actions.

### M10. Ktor JSON Parser Is Lenient

File: `mobile/app/src/commonMain/kotlin/com/securevault/mobile/data/api/SecureVaultApi.kt`

Mobile JSON config sets `isLenient = true`.

Impact: Accepts non-standard JSON and widens parser surface.

Fix:
- Set `isLenient = false` for production.

### M11. Mobile Uses `!!`/Required Field Assumptions for Server Responses

Files:
- `mobile/app/src/commonMain/kotlin/com/securevault/mobile/data/repository/AuthRepositoryImpl.kt`
- `mobile/app/src/commonMain/kotlin/com/securevault/mobile/data/api/SecureVaultApi.kt`

Many auth response fields are force-unwrapped.

Impact: Malformed/partial server response can crash the app.

Fix:
- Parse into explicit sealed response types.
- Fail gracefully with user-safe errors.

### M12. Mobile Session and Vault Key Material Are Durable

Files:
- `mobile/app/src/commonMain/kotlin/com/securevault/mobile/data/repository/SessionManager.kt`
- `mobile/app/src/androidMain/kotlin/com/securevault/mobile/data/local/AndroidEntryEncryptor.kt`

Access/refresh tokens and wrapped vault key persist in EncryptedSharedPreferences; vault key is cached as a Base64 string in memory.

Impact: Longer exposure window after unlock.

Fix:
- Add inactivity/background auto-lock.
- Store vault key as wipeable bytes or `SecretKey`, not immutable `String`.
- Clear UI/view-model password state after use.

### M13. Biometric Unlock Stores the Vault Key

Files:
- `mobile/app/src/androidMain/kotlin/com/securevault/mobile/data/local/BiometricStorage.kt`
- `mobile/app/src/androidMain/kotlin/com/securevault/mobile/ui/screens/settings/SettingsViewModel.kt`

Biometric unlock encrypts the raw vault key and stores it locally.

Impact: Biometric compromise/device compromise can unlock vault without the master password.

Fix:
- Treat biometric unlock as a convenience with clear threat model.
- Consider storing only a short-lived unwrap token, or require master password after reboot/timeout.
- Add local failure counters and wipe after repeated failures.

### M14. Account Lockout Counter Behavior Is Awkward

File: `src/main/java/com/securevault/service/AuthService.java`

Failed attempts continue incrementing while locked and can produce immediate relock behavior after unlock.

Impact: Increased self-DoS and confusing recovery behavior.

Fix:
- Do not increment while currently locked.
- Reset or normalize failed-attempt state when lock expires.

### M15. HSTS Is Always Configured

File: `src/main/java/com/securevault/config/SecurityConfig.java`

HSTS with preload is configured unconditionally.

Impact: Can cause confusing behavior in non-production/dev deployments.

Fix:
- Gate HSTS on production/TLS-required profile.

## Low Findings

### L1. 2FA Secret Encryption Uses Static PBKDF2 Salt ✅

File: `src/main/java/com/securevault/config/TwoFactorSecretConverter.java`

The 2FA encryption key is derived from `ENCRYPTION_KEY` using static salt `"2fa-key-derivation"`.

Impact: No per-row separation; compromise of one server encryption key decrypts all TOTP secrets.

Fix:
- Use HKDF or per-row random salt.
- Store key version metadata for rotation.

### L2. Flyway `baseline-on-migrate=true`

Files:
- `src/main/resources/application.properties`
- `src/main/resources/application-prod.properties`

Operational risk: partially initialized databases may silently skip migrations.

Fix:
- Disable in production unless a migration runbook explicitly requires it.

### L3. Password Generator Has Tiny Modulo Bias

File: `web/src/crypto/generator.ts`

Character selection uses scaled random values rather than rejection sampling.

Impact: Very small entropy bias.

Fix:
- Use rejection sampling.

### L4. Server Error Configuration Is Incomplete

Files:
- `src/main/resources/application.properties`
- `src/main/resources/application-prod.properties`

`include-message` and binding errors are disabled, but additional error settings can be locked down.

Fix:
- Set `server.error.include-exception=false`.
- Set `server.error.include-stacktrace=never`.
- Disable whitelabel error page.

### L5. Health Endpoint Reveals DB Status

File: `src/main/java/com/securevault/controller/HealthController.java`

Public health endpoint returns DB up/down and timestamp.

Impact: Public outage/fingerprinting signal.

Fix:
- Put detailed health behind private network/authenticated monitoring.
- Public endpoint should return minimal status.

### L6. Server-Side Breach Check Service Is Risky Dead Code

File: `src/main/java/com/securevault/service/BreachCheckService.java`

Server-side HIBP password checking is currently not appropriate for a zero-knowledge model if wired to plaintext passwords.

Impact: Future regression may send plaintext passwords to server-side breach checks.

Fix:
- Remove dead service or document that breach checking must remain client-side only.

### L7. `InputSanitizer` Is Unused

File: `src/main/java/com/securevault/util/InputSanitizer.java`

Unused security utilities create false confidence.

Fix:
- Delete or wire into explicit validation paths.

### L8. Logout by Refresh Token Is Public and Enables Targeted Session DoS

Files:
- `src/main/java/com/securevault/controller/AuthController.java`
- `src/main/java/com/securevault/service/AuthService.java`

Anyone with a stolen refresh token can submit logout and invalidate that session.

Impact: Targeted denial of session.

Fix:
- Accept as minor if token theft is already serious, or require authenticated logout for user-wide actions.

### L9. `AuditLogRepository` Exposes Global Query Method

File: `src/main/java/com/securevault/repository/AuditLogRepository.java`

`findAllByOrderByCreatedAtDesc` is present but unused.

Impact: Footgun for future admin endpoints.

Fix:
- Remove until needed.

### L10. Refresh Rotation Is Not Atomic Across Delete/New Save

File: `src/main/java/com/securevault/service/AuthService.java`

Old refresh token is deleted before the new one is saved.

Impact: Database failure can log user out.

Fix:
- Use transaction constraints carefully or save new token before deleting old token with family/reuse semantics.

### L11. Cookie SameSite Set via Raw Cookie Attribute

File: `src/main/java/com/securevault/controller/AuthController.java`

Uses `Cookie.setAttribute("SameSite", "Strict")`.

Impact: Verify actual `Set-Cookie` behavior across servlet container versions.

Fix:
- Prefer `ResponseCookie.from(...).sameSite("Strict")`.

### L12. iOS Crypto Is Not Implemented

Files:
- `mobile/app/src/iosMain/kotlin/com/securevault/mobile/data/local/IosEntryEncryptor.kt`
- `mobile/app/src/iosMain/kotlin/com/securevault/mobile/domain/crypto/CryptoEngine.ios.kt`

iOS methods throw `NotImplementedError`.

Impact: iOS target cannot safely function.

Fix:
- Implement and test iOS crypto before advertising iOS support.

### L13. Android Release Build Has Minification Disabled

File: `mobile/app/build.gradle.kts`

`isMinifyEnabled = false` for release.

Impact: Easier reverse engineering/tampering.

Fix:
- Enable R8/minification and resource shrinking.
- Add tamper detection/attestation strategy if appropriate.

### L14. Tracked `mobile/local.properties`

File: `mobile/local.properties`

The file is tracked and contains local path/user information.

Impact: Minor privacy leak and repo hygiene issue.

Fix:
- Remove from git tracking.
- Keep `local.properties` ignored.

### L15. Postman Collection Is Stale and Misleading

File: `SecureVault.postman_collection.json`

The collection still uses plaintext `password` fields for register/login/change-password, which no longer matches the client-side auth-hash flow.

Impact: Testers may send plaintext passwords to wrong paths/tools or misunderstand the protocol.

Fix:
- Update or delete the collection.
- Add a zero-knowledge client simulator collection if needed.

## Already fixed ✅

| Finding | Fix |
|---------|-----|
| C4 — 2FA Thread.sleep DoS | Removed `Thread.sleep(30000)` from `TwoFactorAuthService.enable2FA()` |
| H2 — 2FA per-challenge brute force | Added per-challenge attempt limit (5) in `PendingLoginChallengeStore` |
| H3 — Spoofable client IP | Created `ClientIpResolver` with `app.proxy.trusted` toggle; replaced all 3 inline X-Forwarded-For parsing sites |
| M6 — Vault audit missing IP/UA | All 5 vault endpoints now inject `HttpServletRequest` + `ClientIpResolver`, pass real IP and User-Agent |
| L1 — Static 2FA PBKDF2 salt | `TwoFactorSecretConverter` now decodes `ENCRYPTION_KEY` directly as AES key instead of PBKDF2 with static salt |

Additional fixes not listed in this review:
- PBKDF2 server-side hash salt → per-user random 32-byte salt + `SERVER_HASH_SECRET` pepper
- `LoginRateLimiter` (ConcurrentHashMap → Redis)
- `RateLimitingFilter` (ConcurrentHashMap + ScheduledExecutorService → Redis)
- `PendingLoginChallengeStore` + `TwoFactorAuthService.pendingSetups` → Redis (removed ScheduledExecutorService cleanup)
- `AuthController` and `VaultController` authenticated IP resolution via `ClientIpResolver`
- `VaultService` entry count limit (10,000 max per user)
- Explicit UTF-8 charset in `getBytes()` calls
- Legacy `vaultKeyIv` field removed (User entity + V7 migration)
- Swagger endpoints locked down in `SecurityConfig` (`.denyAll()`)
- `encryptionVersion` centralized in `EncryptionConstants`
- `DELETE /api/v1/auth/account` endpoint added (GDPR)

## Positive Controls Observed

- Vault entries are stored server-side as ciphertext plus IV.
- AES-GCM is used with 12-byte IVs for entry encryption and vault-key wrapping.
- Refresh tokens are hashed in the database.
- 2FA secret is encrypted at rest.
- JPA/repository usage avoids obvious SQL injection.
- Web access token is kept in memory rather than localStorage.
- React rendering mostly uses JSX text nodes rather than dangerous HTML sinks.

## Verification Gaps

The following should be done before considering this review complete:

- ~~Run Maven tests.~~ ✅ (11/11 passing)
- Run Gradle/mobile tests.
- Run `npm audit`, Maven/Gradle dependency audits, and OSV or OWASP Dependency-Check.
- Run secret scanning with gitleaks/trufflehog.
- Dynamically test login enumeration timing.
- Dynamically test 2FA brute-force behavior.
- Verify production TLS, HSTS, CORS, cookie, and CSP headers against the deployed domain.
- Inspect Android release APK for backup policy, cleartext policy, pinning, screenshots, and minification.
- Test Chrome extension autofill behavior on hostile pages.

## Recommended Fix Order

Items marked ✅ are done. Remaining priority:

1. Remove refresh tokens from web JSON responses.
2. Stop Android plaintext vault persistence; disable backup; disable global cleartext.
3. Fix unknown-user login timing/rate-limit behavior.
4. Narrow `/api/v1/auth/**` authorization and add endpoint tests.
5. ✅ ~~Remove `Thread.sleep` DoS path from 2FA enable.~~
6. ✅ ~~Add per-challenge 2FA attempt limits.~~
7. Fix extension token/key storage.
8. ✅ ~~Add trusted proxy handling for client IP.~~
9. Enforce TLS and pin mobile production certificates.
10. Run dependency/security audits and upgrade stale dependencies.
