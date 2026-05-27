# SecureVault — Security Review

**Date:** 2026-05-27
**Last updated:** 2026-05-27 (fixes applied)
**Scope:** Backend (Spring Boot), Web (React/Vite), Chrome Extension, Mobile (Kotlin Multiplatform Android/iOS), Deployment (Docker/Nginx), DB schema.

> **Legend:** ✅ = Fixed & deployed. Items without marker are still open.

The zero-knowledge foundation is well-designed (Argon2id KEK, AES-256-GCM with random per-entry IVs, server stores only opaque ciphertext, refresh tokens stored as SHA-256 hashes, 2FA secret encrypted at rest, PBKDF2 600k pepper on the server). However, multiple client-side issues persistently leak plaintext outside the server, undermining the model end-to-end.

---

## Summary of Severity Counts

| Severity | Total | ✅ Fixed | ❌ Remaining |
|----------|-------|----------|--------------|
| Critical | 8     | 1        | 7            |
| High     | 13    | 2        | 11           |
| Medium   | 18    | 0        | 18           |
| Low      | 20    | 1        | 19           |
| **Total**| **59**| **4**    | **55**       |

---

## CRITICAL

### C1. Refresh token returned in JSON body, defeating HttpOnly cookie protection
- `AuthResponse.refreshToken` is populated and serialized on every login / register / 2FA / refresh response (`AuthResponse.java:12`, set in `AuthService.generateAuthResponse:336`; same in `ChangePasswordResponse.java:12`, `TwoFactorLoginResponse.java:31`).
- The web client also sets it as an HttpOnly cookie (`AuthController.setRefreshTokenCookie:175`), but the value still lives in the JSON the browser receives. **Any XSS that runs `fetch('/api/v1/auth/refresh')` and reads `res.json()` exfiltrates the refresh token in cleartext** — completely defeating HttpOnly+SameSite.
- Fix: for the web client, omit `refreshToken` from the JSON body. The mobile client genuinely needs it; split DTOs per channel or null it out in the cookie path.

### C2. Email enumeration via timing and missing rate-limiting on unknown users
- `AuthService.login:106` throws `BadCredentialsException` immediately on `findByEmail(email).orElseThrow(...)`. Existing-user requests run PBKDF2(600k) + Argon2id; non-existing requests skip all crypto. The timing delta (hundreds of ms vs sub-ms) is trivially measurable.
- Worse, `loginRateLimiter.recordFailure(...)` is only called inside the password-mismatch branch (`AuthService.java:115-116`). **Login attempts against random / non-existent emails do not increment the failure counter** — combined with the timing oracle, accounts can be enumerated at high throughput, limited only by the generic 60 req/min IP rate limit.
- Fix: when the user is not found, still perform a dummy `serverSideHash(...)` against a sentinel value and call `recordFailure(clientIp)` — throw the same exception with the same elapsed-time profile.

### C3. Spring Security `permitAll` for `/api/v1/auth/**` exposes change-password
- `SecurityConfig.java:32` grants `permitAll` to **everything** under `/api/v1/auth/**`. `POST /api/v1/auth/change-password` is in that namespace.
- The controller relies on `@AuthenticationPrincipal UserDetails userDetails` being non-null; `UserUtils.getUserId(null)` currently throws NPE → 500 so the endpoint isn't directly exploitable today. But it is **one accidental refactor away from a critical auth bypass**.
- Fix: scope `permitAll` to the explicit endpoints (`/auth/register`, `/auth/login`, `/auth/verify-2fa`, `/auth/refresh`, `/auth/logout`) and require auth for `/auth/change-password`.

### C4. `Thread.sleep(30000)` in 2FA enable path = trivial DoS ✅
- `TwoFactorAuthService.enable2FA:102` blocks the request thread for 30 seconds whenever a user submits a `secondCode` that differs from `code`. With default Tomcat thread pool (~200), 200 such requests exhaust the pool and the service becomes unresponsive to every other user — at only ~7 requests per second.
- Fix: do not sleep. Require the second code to be from a different 30-second TOTP window via a non-blocking timestamp check, or drop the second-code feature entirely.

### C5. Android local cache stores vault entries in PLAINTEXT — breaks zero-knowledge
- `VaultEntryEntity.kt` is a Room table with **plaintext** `title, username, password, url, notes` columns. `CachedVaultRepository` writes decrypted entries to this table via `syncFromRemote(...)` and `toEntity(true)` on every API success.
- The DB is wrapped with SQLCipher (`SecureVaultDatabase`), but the passphrase is auto-generated and stored in `EncryptedSharedPreferences` (`DatabaseKeyManager.kt:60`). On a rooted device, after KeyStore key extraction, or via Android backup (C7), the SQLCipher passphrase and the database can both be exfiltrated together → **full vault recovery without the master password**.
- Fix: store the ciphertext + IV (the same `encryptedData` blob the server stores). Decrypt only in memory when needed. Never persist plaintext fields.

### C6. `VaultCache.kt` writes plaintext passwords to UNENCRYPTED DataStore
- `VaultCache.saveEntries(...)` JSON-serializes the full `VaultCacheEntry { id, title, username, password, url, notes, folder }` and writes to `context.vaultDataStore` (a normal Preferences DataStore at `/data/data/<pkg>/files/datastore/vault_cache.preferences_pb`).
- DataStore has **no encryption at rest**. Combined with `allowBackup=true` (C7), `adb backup` or a backup-aware malicious app can extract the file. On a rooted device, no special permissions are required.
- Strictly worse than C5 because there's not even SQLCipher in the way.
- Fix: delete `VaultCache.kt` if `CachedVaultRepository` is the authoritative cache, or convert it to store only ciphertext blobs.

### C7. Android `allowBackup="true"` on a password manager
- `AndroidManifest.xml:9`. Allows `adb backup` and Google Auto Backup to copy app data — including the plaintext caches in C5/C6 and the EncryptedSharedPreferences. For any password manager, this should be `android:allowBackup="false"` and `android:fullBackupContent="@xml/backup_rules"` with an exclude-all policy.

### C8. Android `network_security_config.xml` permits cleartext globally
- The `<base-config cleartextTrafficPermitted="true">` rule applies to **every** host, not just localhost. A misconfigured DNS, captive portal, or downgrade attack against `vault.tanay.pro` (or any host) will succeed silently — leaking tokens and (during login) the Argon2 auth hash on the network.
- Fix: set `<base-config cleartextTrafficPermitted="false">` and keep the explicit localhost / 10.0.2.2 exemption in `<domain-config>` (which already overrides).

---

## HIGH

### H1. Client uses email as Argon2 salt
- `AuthContext.tsx:123` and `web/src/crypto/argon2.ts:8` derive the auth hash with `salt = email`. Same email + same password across deployments produces the same hash; an attacker who knows the email can pre-compute Argon2id work for popular passwords against that specific user.
- Same issue in mobile: `cryptoEngine.generateAuthHash(password, email)` in `AuthRepositoryImpl.kt:37,72`.
- Fix: store and serve a random `authSalt` (already plumbed in the API!) and use it client-side instead of the email. Migrate existing users on next login or password change.

### H2. No TOTP code rate-limit; 2FA challenge not consumed on failed code ✅
- `verifyTwoFactorLogin` does not consume the challenge on failure (intentional per commit `88f7fa4`). Only the generic per-IP/email login rate limiter applies. The challenge lives for 5 minutes (`PendingLoginChallengeStore.CHALLENGE_TTL_SECONDS = 300`). With 60 req/min, an attacker who has stolen the password can submit up to ~300 codes per challenge window before the global IP limit kicks in.
- Fix: track per-challenge attempt count; consume the challenge after N (e.g., 5) failed attempts; tighten per-IP/email rate limit for `/verify-2fa` to ~5/min.

### H3. Spoofable client IP → rate-limit and audit bypass ✅
- `RateLimitingFilter.getClientIdentifier:68` and `AuthController.getClientIp:207` trust `X-Forwarded-For` / `X-Real-IP` unconditionally. The app is configured with `server.forward-headers-strategy=framework` only in the prod profile, but if deployed without a stripping reverse proxy, **any client can spoof its IP via a header**, defeating rate limiting and poisoning audit logs.
- Fix: use Spring's `ForwardedHeaderFilter` with an allow-list of trusted proxy IPs (`server.tomcat.remoteip.internal-proxies`); never trust the headers for direct connections.

### H4. No refresh-token reuse detection / family revocation
- `AuthService.refreshToken:189` performs token rotation but on a repeated submission of the already-rotated token, it just throws `Invalid refresh token`. The log warns "Refresh token reuse detected — hash not found in DB" but takes no action. If an attacker steals a refresh token and uses it before the victim, the attacker rolls forward and the victim sees a generic failure — no global session revocation, no alert.
- Fix: bind tokens into a "family" (carry a family ID through rotations); on reuse, revoke the entire family and force re-auth.

### H5. Master key bytes persisted to `chrome.storage.session`
- The extension exports the raw vault key via `crypto.subtle.exportKey('raw', vaultKey)` and stores it in `chrome.storage.session` (`background.ts:93-94`, `storage.ts:48-50`). Session storage is accessible to any code running with extension privileges (a malicious dependency update, debugging tools, profile compromise). Holding raw key bytes outside of a non-extractable `CryptoKey` eliminates WebCrypto's isolation benefit.
- Fix: store the key as a non-extractable `CryptoKey` only in the SW's memory; require unlock on SW restart instead of persisting raw bytes.

### H6. Auth audit JSON built with manual escaping
- `AuditService.logFailedLogin:106` constructs `details` JSON by hand-escaping `\, ", \n, \r, \t`. It does **not** escape other control chars (U+0000–U+001F except the four listed). PostgreSQL JSONB will reject these and the audit insert will fail — an attacker can supply such bytes in the `email` field of a failed login to suppress the audit log entry.
- Fix: use Jackson (`objectMapper.writeValueAsString(...)`) to build `details`.

### H7. CORS `setAllowedOriginPatterns` + `allowCredentials=true`
- `CorsConfig.java:17` uses `setAllowedOriginPatterns` and `allowCredentials=true`. Current values don't contain wildcards, but the pattern API silently allows them. This is a footgun next to credentialed requests — a future `https://*.tanay.pro` entry would let any subdomain pose as a credentialed origin.
- Fix: use `setAllowedOrigins` (exact list).

### H8. Mobile API client has no certificate / public-key pinning
- `SecureVaultApi.create("https://vault.tanay.pro")` uses Ktor's default `HttpClient` with no SSL pinning. Combined with the Android system trust store, any installed user CA or compromised public CA can MITM the connection and capture the bearer/refresh tokens.
- Fix: add `<pin-set expiration="...">` for `vault.tanay.pro` in the Android network security config (with backup pins) and OkHttp/Ktor `CertificatePinner` programmatically.

### H9. MainActivity does not set `FLAG_SECURE`
- `MainActivity.kt` does not call `window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)`. Vault content is captured in the Android task-switcher preview (visible to anyone holding the device), is screenshot/screen-recordable, and is visible during screen casting / Google Assistant capture.
- Fix: set `FLAG_SECURE` globally, or at minimum on the vault, unlock, and add/edit screens.

### H10. Mobile refresh-token flow depends on the leaked refresh token in JSON body
- `SecureVaultApi.refreshAccessToken:284` POSTs the refresh token in the body and re-reads `authData.refreshToken` from the body. Same data path as C1. The backend cannot remove the body field without breaking mobile — fix per-client (omit body for web, keep for mobile).

### H11. Mobile `getOrCreateDeviceId` uses `kotlin.random.Random` (non-cryptographic)
- `AuthRepositoryImpl.getOrCreateDeviceId:248`. Device IDs are used to scope refresh-token revocation; predictable device IDs let an attacker correlate or impersonate device sessions. Use `SecureRandom`.

### H12. `SecureVaultDatabase.getInstance(context)` overload creates an UNENCRYPTED DB
- `SecureVaultDatabase.kt:40` ships a second `getInstance(context)` overload that builds a `Room.databaseBuilder(...)` *without* `SupportFactory(passphrase)`. Currently unreferenced, but it's a one-typo footgun: any future caller of the wrong overload silently writes the entire (plaintext, per C5) cache to plain SQLite.
- Fix: delete it.

### H13. `fallbackToDestructiveMigration()` enabled on the cache DB
- `SecureVaultDatabase.kt:33,47`: on any schema upgrade, the entire local cache is wiped. Acceptable since it's a cache, but a corrupt DB also silently destroys whatever is there — a user signing in offline with stale state could lose unsynced changes.

---

## MEDIUM

### M1. SSL not enforced by default
- `application.properties:46` `security.require-ssl=false`; `server.ssl.enabled=false`. If the operator misconfigures the reverse proxy, the app serves plaintext — including bearer tokens, refresh cookies (whose `setSecure(true)` silently drops them anyway), and vault traffic. No startup-time assertion that TLS is in front of the app in prod.
- Fix: set `require-ssl=true` in `application-prod.properties`; add a startup check that rejects boot if neither `server.ssl.enabled` nor a trusted forwarded-proto path is configured.

### M2. Sensitive PII (emails) logged everywhere
- `AuthService` logs `user.getEmail()` on register / login / lock / password change; `AuthController` logs email on every login / 2FA attempt; `RequestLoggingInterceptor` logs User-Agent and IP. Log file (`logs/securevault.log`, 10MB × 30 history) keeps a large amount of personal data on disk.
- Fix: log a hash or user UUID instead of email; use MDC for request IDs; redact User-Agent in standard log lines.

### M3. `Cache-Control: no-store` applied to every backend response
- `SecurityHeadersFilter.java:39` sets `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` on **all** responses. Fine for backend (API-only), and nginx (`nginx.conf:21`) only does this on `index.html` — verify the headers aren't overridden by the proxy chain.

### M4. No request size limits — DoS via large JSON
- `VaultEntryRequest` caps `encryptedData` at 100KB. But `ChangePasswordRequest.wrappedVaultKey`, `RegisterRequest.wrappedVaultKey / authHash / encryptionSalt`, and `DeviceRequest.publicKey` are unbounded. No global Tomcat `max-http-form-post-size` set.
- Fix: add `@Size` to every user-controlled string field; cap `server.tomcat.max-http-post-size` to a low number (e.g., 256KB).

### M5. JWT lacks `iss` / `aud` and access tokens are not revocable
- `JwtTokenProvider.generateAccessToken:52` issues a JWT with `sub`, `email`, `pwdUpdatedAt` only. **No issuer or audience claim, no validation of them.** Access tokens are not revocable except via the `pwdUpdatedAt` check; logout, 2FA changes, etc. don't invalidate them. Default 1-hour TTL is long for an unrevocable token.
- Fix: add and validate `iss` / `aud`; shorten TTL to 5–15 minutes.

### M6. `Permissions-Policy` missing modern directives
- `SecurityHeadersFilter.java:36` blocks camera/mic/geo/payment but not `interest-cohort=()`, `browsing-topics=()`, `attribution-reporting=()`. For a password manager, lock these down.

### M7. CSP allows `'unsafe-inline'` styles
- `SecurityHeadersFilter.java:24` and `nginx.conf:11` both include `style-src 'self' 'unsafe-inline'`. Leaves a CSS injection vector for exfiltration via background-image URLs etc.
- Fix: switch to nonce-based or hash-based `style-src`.

### M8. Account lockout: one-failure window after unlock
- `AuthService.handleFailedLogin:311` increments `failedLoginAttempts` even when the account is already locked. Once unlocked, the **next failure starts adding to the previous count immediately** — users get only one failed attempt after a 15-min lockout before being relocked.

### M9. HSTS preload always enabled (even in dev)
- `SecurityConfig.java:37` enables `maxAge=1y, includeSubDomains, preload` at all times. In a development deployment on localhost / non-HTTPS, a misconfiguration can pin browsers to HTTPS for `localhost` for a year.
- Fix: gate HSTS on `security.require-ssl=true` or the prod profile.

### M10. `verifyTwoFactorLogin` does not check `loginRateLimiter.isBlocked(...)` before validating challenge
- `AuthService.verifyTwoFactorLogin:158` skips the `isBlocked(clientIp)` / `isBlocked(email)` checks that `login` performs. The first ~5 attempts always go through unimpeded regardless of whether the IP was already blocked.
- Fix: add the same two `isBlocked` checks at the top of `verifyTwoFactorLogin`.

### M11. Master password held in React/Compose state until form reset
- `LoginPage.tsx:48` keeps `data.password` in the closure of `onLoginSubmit`; React Hook Form holds the raw string in `formState.values` until reset. React DevTools / a heap dump exposes it. Same in extension popup (`script.ts:88`).
- Fix: clear form state immediately after submit; use the password only long enough to call `crypto.subtle.importKey` and drop it.

### M12. Ktor JSON parser uses `isLenient = true`
- `SecureVaultApi.create:374` enables Ktor `isLenient = true`. Lenient JSON accepts unquoted keys/values and trailing commas, widening the parser surface for tampered responses.
- Fix: set `isLenient = false`.

### M13. `parseAuthResponse` / `refreshToken()` use `!!` non-null assertions on server fields
- `AuthRepositoryImpl.kt:49-55, 96-104, 134-141`: many `authResponse.accessToken!!`. A malformed or partial server response causes instant NPE → app crash — a low-effort DoS against any authenticated client if the backend ever returns a partial body.
- Fix: nullable handling with user-facing errors.

### M14. Mobile session is durable; no auto-lock based on inactivity
- `SessionManager` persists access / refresh tokens and wrappedVaultKey to EncryptedSharedPreferences with no expiry. Vault key is held in `AndroidEntryEncryptor.cachedVaultKey` in memory — but the plaintext entries are still in the Room cache (C5), so even "locked" the cache holds the data. No analogue to web's `useAutoLock`.
- Fix: implement screen-lock + cache wipe based on inactivity / app background.

### M15. `network_security_config` trusts only system CAs but has no `<pin-set>` and no `<debug-overrides>`
- See H8. Tighten with explicit production pins; add debug overrides for emulator testing.

### M16. `BiometricStorage.onAuthenticationFailed` does not rate-limit
- The biometric prompt allows the OS-level retry policy to govern attempts. Consider incrementing a local counter and wiping the encrypted vault key after N consecutive failures.

### M17. `VaultCache.getLastSyncTime()` hangs forever
- `data.collect { ... }` inside a `suspend fun` is unbounded. Returns only when the flow completes — which it never does. Functional bug; if anything relies on this to gate a cache wipe, it never runs.

### M18. `CachedVaultRepository.withDao` catches any exception and deletes the entire local DB
- `CachedVaultRepository:60-72`: on first exception, the local DB and passphrase are wiped, then the operation is retried. A transient I/O error → silent destruction of the cache and forced re-sync of (plaintext, per C5) entries to disk.
- Fix: catch only SQLCipher-specific exceptions.

---

## LOW

### L1. Static salt for PBKDF2 in 2FA secret encryption ✅
- `TwoFactorSecretConverter.java:33` derives the AES key with PBKDF2 from `ENCRYPTION_KEY` using literal string `"2fa-key-derivation"` as the salt. Acceptable with a high-entropy `ENCRYPTION_KEY` but provides no per-user separation; if `ENCRYPTION_KEY` ever leaks, every user's 2FA secret is decryptable.
- Fix: use a random per-row salt stored alongside the ciphertext, and/or use HKDF.

### L2. `flyway.baseline-on-migrate=true` in prod
- `application.properties:17` baselines new envs against the current schema, which can quietly skip migrations on a partially-migrated DB. Operational risk; not a code vuln.

### L3. Generated password uses biased modulo distribution
- `web/src/crypto/generator.ts:17` — `Math.floor(crypto.getRandomValues(...)[0] / (0xffffffff + 1) * charset.length)` is biased for charsets whose size doesn't divide 2^32 (bias is tiny, ~1e-8). Use rejection sampling.

### L4. `server.error.*` not fully locked down
- Add `server.error.include-exception=false`, `server.error.include-stacktrace=never`, `server.error.whitelabel.enabled=false`.

### L5. Health endpoint enumerable
- `/api/v1/health` is `permitAll` and returns DB up/down + timestamp. The 503 response on DB failure can fingerprint outages. Consider serving on a separate, non-public port.

### L6. Public extension content script on `http://*/*`
- `web/extension/manifest.json:26` injects on every page (necessary for autofill). Combined with H5, the blast radius of a compromised extension dependency is the entire vault.
- Fix: prefer action-triggered injection over universal content scripts where possible.

### L7. Server-side `BreachCheckService` is dead code
- HIBP check cannot be useful in a zero-knowledge model; invoked nowhere. Remove it or risk it being wired up later in a way that does see plaintext passwords.

### L8. `InputSanitizer` is unused
- Defined but never imported anywhere. Delete or wire it in.

### L9. `Logout` accepts arbitrary refresh tokens without auth
- `AuthController.logout` will delete a refresh token if anyone presents the right hash. Hashes are non-guessable, but an attacker with one stolen refresh token can spam logout to invalidate the victim's session at will (targeted DoS).

### L10. Repository exposes `findAllByOrderByCreatedAtDesc(Pageable)`
- `AuditLogRepository.java:18` returns all audit logs across all users. No endpoint uses it today, but it's a footgun for future admin endpoints.

### L11. `RefreshToken` rotation has no atomicity guarantee
- `AuthService.refreshToken:211` deletes the old token, then `generateAuthResponse` saves a new one. If the second step fails (DB blip, unique-constraint collision), the user is silently logged out.

### L12. Google Fonts loaded from CDN with no SRI
- `web/index.html:9` pulls fonts from `fonts.googleapis.com`, but the CSP only allows `font-src 'self'` — the request is blocked anyway. Either remove the tag or self-host.

### L13. JWT `jti` set but no deny list
- `JwtTokenProvider.generateAccessToken:57` puts a `jti`, but there's no JTI deny list and no revocation. Acceptable given short TTL plan, but document it.

### L14. Cookie API used directly for `SameSite` attribute
- `AuthController.setRefreshTokenCookie:182` uses `Cookie.setAttribute("SameSite", "Strict")` rather than `ResponseCookie.from(...).sameSite("Strict")`. Works on modern Spring Boot, but verify with the actual `Set-Cookie` header.
- Fix: prefer `ResponseCookie`.

### L15. Inconsistent `server.address` default
- `application.properties` defaults to `127.0.0.1`, `application-prod.properties` and docker-compose override to `0.0.0.0`. Two sources of truth led to the recent bind-address fix (commit `32a36ec`).

### L16. iOS implementation is non-functional
- `IosEntryEncryptor.kt` and `CryptoEngine.ios.kt` throw `NotImplementedError` on every method. README and product docs imply iOS support; an iOS user would crash on launch.

### L17. Verbose backend error surfacing
- Many `Result.Error(it.message ...)` paths surface backend error messages in the mobile UI; `RequestLoggingInterceptor` on the server logs verbose request data to logcat-readable scope.

### L18. `Json { prettyPrint = true }` for HTTP client
- `SecureVaultApi.create:373` sends pretty-printed JSON on every request. Tiny bytes wasted; unusual choice.
- Fix: compact JSON.

### L19. No Play Integrity / App Attest / root detection
- For an Android password manager, attestation of app + device integrity is now table stakes. Currently nothing — a modified/repackaged app speaks to the same backend identically.

### L20. `VaultEntryDao.searchEntries` uses leading `%`
- Room parameterizes correctly, but the leading `%` prevents index use. Performance footgun on large vaults.

---

## What the codebase gets RIGHT

- AES-256-GCM with random 12-byte IV per entry/wrap — correct usage, no IV reuse.
- Constant-time hash compare via `PasswordService.constantTimeEquals` — proper byte-level XOR.
- Refresh tokens stored in DB as SHA-256 hashes (raw JWT never persisted).
- JPA + parameterized queries everywhere; no SQL injection vectors observed.
- 2FA secret encrypted at rest with AES-GCM (`TwoFactorSecretConverter`).
- HttpOnly + Secure + SameSite=Strict refresh cookie scoped to `/api/v1/auth`.
- Per-user vault key, rotated on password change; old sessions invalidated via `pwdUpdatedAt` JWT claim.
- Web frontend keeps decrypted material in `vaultKeyRef` (closure) and `_cryptoMaterial` (module local), not localStorage.
- Argon2id parameters (4 iterations, 64 MiB, parallelism 4) are reasonable for client-side.
- 2FA challenge model (separate challenge ID, TTL) is solid.
- Per-user data isolation enforced in every vault/device/audit endpoint.
- Spring `ddl-auto=validate` prevents accidental schema drift.

---

## Aggregate Picture

The server-side zero-knowledge model is well-designed. The **client side persistently leaks plaintext** in three places:

| Surface       | Issue                                                                 | Worst-case impact                              |
|---------------|-----------------------------------------------------------------------|------------------------------------------------|
| Web           | Refresh token in JSON body (C1)                                       | XSS ⇒ refresh token stolen                     |
| Extension     | Raw vault key bytes in `chrome.storage.session` (H5)                  | Extension compromise ⇒ vault                   |
| Android       | Plaintext entries in Room + DataStore (C5, C6) + backup enabled (C7) + cleartext base config (C8) | Device compromise ⇒ full vault, no master password needed |

---

## Already fixed ✅

| Finding | Fix |
|---------|-----|
| C4 — Thread.sleep DoS | Removed `Thread.sleep(30000)` from `TwoFactorAuthService.enable2FA()` |
| H2 — 2FA brute force | Added per-challenge attempt limit (5) in `PendingLoginChallengeStore` |
| H3 — IP spoofing | Created `ClientIpResolver` with `app.proxy.trusted` toggle; replaced all 3 inline X-Forwarded-For parsing sites |
| L1 — Static PBKDF2 salt in 2FA encryption | `TwoFactorSecretConverter` now decodes `ENCRYPTION_KEY` directly as AES key instead of PBKDF2 with static salt |

Additional fixes not in this review:
- PBKDF2 salt → per-user random 32-byte salt + serverHashSecret as pepper
- `LoginRateLimiter` (ConcurrentHashMap → Redis)
- `RateLimitingFilter` (ConcurrentHashMap + ScheduledExecutorService → Redis)
- Vault audit logs now include real IP and User-Agent (were null)
- `AuthController` IP resolution via `ClientIpResolver`
- `VaultService` entry count limit (10,000 max per user)
- `PendingLoginChallengeStore` + `TwoFactorAuthService.pendingSetups` → Redis (removed ScheduledExecutorService cleanup)
- Explicit UTF-8 charset in `getBytes()` calls
- Legacy `vaultKeyIv` field removed (User entity + V7 migration)
- Swagger endpoints locked down in `SecurityConfig` (`.denyAll()`)
- `encryptionVersion` centralized in `EncryptionConstants`
- `DELETE /api/v1/auth/account` endpoint added (GDPR)

## Suggested Fix Priority

1. **Fix C1–C8 immediately** — C4 is fixed; C1 (refresh in JSON), C2 (email enumeration), C3 (permitAll scope), C5–C8 (Android) remain.
2. Then **H1–H13** — H2, H3 fixed; H1 (email as salt), H4 (refresh reuse detection), H5 (extension key storage), H6 (audit JSON), H8 (cert pinning), H9 (FLAG_SECURE), H11 (SecureRandom for device ID), H12 (delete unencrypted DB overload) remain.
3. Mediums and lows as time allows.
