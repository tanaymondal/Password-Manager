# Features TODO

## Phase 0 — Critical Security Bugs

- [ ] **2FA challenge binding** — `POST /auth/verify-2fa` accepts `{email, code}` with no challenge nonce or expiry. Anyone with email + valid TOTP code can log in without the password step. Add a server-generated challenge token bound to the pre-2FA login session.
- [ ] **Encryption material leaked before 2FA** — `login()` returns `encryptionSalt` and `wrappedVaultKey` even when 2FA is required. An attacker with correct password but no TOTP gets key-wrapping material. Return these only after 2FA verification completes.
- [ ] **Encrypt TOTP secrets** — `User.twoFactorSecret` stored as plaintext `String` in DB. A database breach exposes all 2FA secrets. Encrypt at rest with a server-side key.
- [ ] **Rate limit 2FA verification** — No rate limiting on `verify-2fa`. Allows brute-force of TOTP codes.
- [ ] **Rate limiting is in-memory only** — `LoginRateLimiter` and `RateLimitingFilter` use `ConcurrentHashMap`. State lost on restart, not distributed across replicas. Trusts `X-Forwarded-For` without validation.

## Phase 1 — Security Hardening

- [ ] **Audit failed logins** — `AuditService.logFailedLogin()` is defined but never called. No forensic trace for brute-force attempts.
- [ ] **Vault audit logs missing IP/User-Agent** — Every `auditService.logVaultAccess()` call in `VaultController` passes `null, null`. No forensic data on vault CRUD.
- [ ] **Move secrets out of localStorage** — JWT access token, refresh token, `encryptionSalt`, and `wrappedVaultKey` all in `localStorage` (XSS-readable). Use HttpOnly cookies for refresh tokens; keep access token in memory only.
- [ ] **Add `jti` claim to JWT tokens** — No token ID means no per-token revocation or blacklist.
- [ ] **Reduce access token TTL** — Currently 1 hour. Should be 15 minutes.
- [ ] **Step-up authentication for sensitive operations** — Password change, 2FA disable, device removal, vault DELETE all accept a bare bearer token. Require recent password re-entry or TOTP re-verification.
- [ ] **Add Redis-backed rate limiting** — Replace in-memory `ConcurrentHashMap` with Redis for persistence and distributed support.
- [ ] **Add `visibilitychange` to auto-lock** — `useAutoLock` listens for DOM events but not tab visibility changes. Vault key stays in memory when user switches tabs.
- [ ] **Stop storing master password in sessionStorage** — `autoUnlockPassword` in `sessionStorage` is readable by any XSS or service worker. Derive and cache the vault key instead, discard the master password immediately.

## Phase 2 — Infrastructure & Hardening

- [ ] **Remove hardcoded secrets from docker-compose.yaml** — DB password, JWT secret, Redis password all hardcoded and committed. Use `${VAR}` references or Docker secrets.
- [ ] **Add payload size limits** — `VaultEntryRequest.encryptedData` has no `@Size(max=...)`. Storage exhaustion attack vector.
- [ ] **Resolve CSP inconsistency** — Backend sets `script-src 'self'` (blocks WASM), nginx sets `'wasm-unsafe-eval'` (allows it). Behavior depends on whether request hits nginx or backend directly.
- [x] **Add KDF parameters per user** — `encryptionVersion` exists but no per-user KDF memory/iterations. Future KDF upgrades break existing sessions.
- [ ] **Configure mobile cleartext traffic** — Android `network_security_config.xml` permits cleartext globally. iOS hardcodes `http://` URL.
- [ ] **Disable Android backup** — `android:allowBackup="true"` in AndroidManifest. Device backup can leak app data.
- [ ] **Enable ProGuard/R8** — Android release build has `isMinifyEnabled = false`. No obfuscation or optimization.

## Phase 3 — Tests & CI

- [ ] **Backend unit/integration tests** — Zero test files. Add tests for services (auth, vault, 2FA, breach check), controllers (security filter, rate limiting), and crypto.
- [ ] **Web tests** — Zero test files. Add tests for crypto (Argon2, AES-GCM, strength, generator), contexts (auth, vault), and page components.
- [ ] **Mobile tests** — `CryptoEngineTest.kt` has duplicate method and unresolved import. Fix and expand.
- [ ] **CI pipeline** — No GitHub Actions. Add workflow for `mvn verify`, `npm run build && lint`, secret scanning (Gitleaks), and dependency scanning (Dependabot).

## Phase 4 — UX Features

- [ ] **Browser extension** — Autofill is the killer feature for a password manager. Build Chrome/Firefox extension for credential autofill.
- [ ] **Password health report** — Dashboard showing reused, weak, breached, or old passwords across the vault.
- [ ] **Import/export** — Import from Bitwarden, 1Password, LastPass, Chrome CSV. Export to encrypted JSON or CSV.
- [ ] **Folders / collections / tags** — Organizational structure beyond a flat entry list.
- [ ] **Favorites / pinning** — Mark frequently used entries for quick access.
- [ ] **Account recovery codes** — Generate 10 single-use recovery codes at signup. Master password loss = permanent data loss currently.
- [ ] **Built-in TOTP code generator** — 2FA is supported for login but no in-app TOTP generation for third-party accounts.
- [ ] **Biometric unlock** — Face ID / Touch ID / Android biometrics for vault unlock on mobile. WebAuthn on web.
- [ ] **Onboarding tour** — First-time user flow explaining zero-knowledge model and master password importance.
- [ ] **Dark/light theme toggle** — Only dark theme exists currently.
- [ ] **Bulk operations** — Select-multiple entries for delete, export, move to folder.
- [ ] **Global search** — Vault page has search but no cross-entry search in settings or elsewhere.

## Phase 5 — iOS

- [ ] **Implement iOS encryption** — `IosEntryEncryptor.encrypt()` and `decrypt()` both throw `NotImplementedError`. No working crypto on iOS.
- [ ] **iOS UI** — No iOS app exists. Build with SwiftUI or keep KMP Compose Multiplatform target.
- [ ] **iOS autofill** — Credential Provider extension for iOS autofill.

## Phase 6 — Monitoring & Observability

- [ ] **Structured logging to stdout** — Currently writes to file `logs/securevault.log`. Should log JSON to stdout for container environments.
- [ ] **Metrics** — Add Micrometer + Prometheus for request rates, latency, error rates, active sessions.
- [ ] **Error tracking** — Integrate Sentry for backend and web error monitoring.
- [ ] **Health check improvements** — Add Redis connectivity, migration status to `/api/v1/health`.

## Phase 7 — Deployment & Operations

- [ ] **Kubernetes manifests** — Helm chart or plain YAML for production deployment.
- [ ] **Secrets management** — Integrate external secrets (AWS Secrets Manager, HashiCorp Vault, or at minimum Docker secrets).
- [ ] **Database backup strategy** — Automated backups with point-in-time recovery.
- [ ] **Certificate pinning on mobile** — Pin backend TLS certificate in Android and iOS apps.
- [ ] **Staged deploys** — Blue/green or canary deployment strategy.

## Tech Debt

- [ ] **`JwtAuthenticationFilter` writes response then continues filter chain** — The `return` at line 98 exits the `if` block, not the method. `chain.doFilter()` runs after the response is committed, causing `IllegalStateException`.
- [ ] **`Argon2AuthenticationProvider` is dead code** — Declared in `SecurityConfig` but `AuthController.login()` calls `AuthService.login()` directly, not through `AuthenticationManager`.
- [ ] **`InputSanitizer` is unused** — All methods exist but are never called anywhere.
- [ ] **JWT parsing duplicated** — `getUserIdFromToken`, `getEmailFromToken`, `getClaim`, `validateToken` each parse independently. Single parse + cache would be better.
- [ ] **Duplicate salt generation methods** — `generateSalt()`, `generateAuthSalt()`, `generateEncryptionSalt()` all do the same thing with minor length differences.
- [ ] **Custom base64 in web** — `base64ToBytes` / `bytesToBase64` use `atob`/`btoa` which don't handle binary data reliably. Use `Uint8Array`-compatible base64 or `base64-js` package.
- [ ] **`application.properties` and `application-prod.properties` are identical** — Prod profile adds no value.
- [ ] **Mobile vault key cached as Base64 String** — Cannot be explicitly zeroed. Use `ByteArray` or `SecretKey`.
- [ ] **Android search icon uses wrong icon** — `VaultScreen.kt:90` uses `Icons.Default.Add` instead of search icon. Logout button also uses `Add` icon.
- [ ] **No error boundaries at route level** — `ErrorBoundary.tsx` exists but `App.tsx` doesn't wrap routes with it.
