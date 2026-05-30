# SecureVault — Security Assessment

> In-depth review of the cryptographic design and security posture across all
> components: Rust crypto-core, Java/Spring Boot backend, React web app + browser
> extension, and the Kotlin Multiplatform mobile app (Android + iOS).
>
> **Date:** 2026-05-31 · **Scope:** full repository at time of review.

---

## Overall verdict

The **core architecture is genuinely strong and correctly zero-knowledge**. The
cryptographic design (shared Rust core, Argon2id → HKDF-split → AES-256-GCM key
wrapping) is textbook-correct, and the backend is well-hardened. The weaknesses
are almost entirely at the **edges**: the iOS client and the browser extension
are the soft spots, and they're serious.

| Component         | Rating            | Summary                                                  |
|-------------------|-------------------|----------------------------------------------------------|
| Rust crypto-core  | **Excellent**     | Correct primitives, domain separation, test vectors      |
| Java backend      | **Strong**        | Good auth, peppered hashing, sudo, rate limits, hardened  |
| Web app (React)   | **Good**          | Solid token model; XSS blast radius + no auto-lock wired |
| Browser extension | **Weak**          | Autofill/credential-leak + storage issues (worst part)   |
| Android           | **Good**          | Keystore-bound biometrics, SQLCipher, FLAG_SECURE        |
| iOS               | **Broken at rest**| Vault key stored in plaintext NSUserDefaults             |

---

## What's done well (the strong foundation)

### Cryptography (`crypto-core/src/lib.rs`, `kdf.rs`, `aead.rs`)
- **True zero-knowledge.** Server only ever stores opaque AES-256-GCM blobs + a
  *wrapped* vault key. `VaultService` never sees plaintext, and the KEK never
  leaves the client.
- **Argon2id at 96 MiB / t=3 / p=4** (`params.rs`) — well above OWASP minimums,
  run client-side.
- **Clean key hierarchy with domain separation:** one Argon2 call → master key →
  `HKDF-Expand` into a server *auth hash* (`info="auth"`) and the *KEK*
  (`info="kek"`). Knowing the server-stored auth hash reveals nothing about the
  KEK. Same model Bitwarden uses, implemented correctly.
- Random 256-bit vault key, random 12-byte GCM nonces per encryption, shared
  Rust core gives Android/iOS/web/test-vector parity.

### Backend auth (`AuthService`, `JwtTokenProvider`, `JwtAuthenticationFilter`)
- **Server-side pepper:** the client's Argon2 output is re-hashed with
  `HMAC-SHA256(key=clientAuthHash, msg=serverSecret + salt)`. A DB-only breach
  can't verify password guesses without the separate `SERVER_HASH_SECRET`.
- **JWT done right:** separate HMAC-derived keys for access vs refresh,
  issuer/audience, `jti`, and a `pwdUpdatedAt` claim that instantly invalidates
  old tokens on password change. Plus a Redis denylist on logout and
  deleted/locked-user checks per request.
- **Refresh tokens** stored only as SHA-256 hashes, rotated on every use, with
  reuse-detection that revokes the whole family; delivered to web via
  `HttpOnly; Secure; SameSite=Strict` cookie scoped to `/api/v1/auth`.
- **Step-up "sudo"** (single-use 5-min token) gates change-password,
  delete-account, upgrade-kdf, delete-all-entries.
- Account lockout (5 fails / 15 min), layered Redis rate limiting, constant-time
  comparisons, timing-equalized login for nonexistent users.
- **No IDOR** — every vault op re-checks `entry.getUserId().equals(userId)`.
- TOTP secret **encrypted at rest** (AES-GCM, `TwoFactorSecretConverter`). HIBP
  via **k-anonymity**. CSPRNG password generator with rejection sampling.
- Hardened config: env-only secrets (no defaults for JWT/pepper/encryption keys),
  `ddl-auto=validate`, error messages suppressed, Swagger `denyAll`, CORS
  allowlist, security-headers filter + CSP, non-root Docker, gitleaks +
  dependabot.

---

## Issues found

### 🔴 Critical

**C1 — iOS stores all key material in plaintext NSUserDefaults**
`mobile/.../iosMain/.../BiometricStorage.ios.kt` and `PlatformStorage.ios.kt`.
The "Keychain" methods are stubs (`migrateToKeychain` = no-op; `writeKeychain` →
`prefs.setObject`). The **raw vault key**, wrapped key, encryption salt, and
refresh token all land in an unencrypted plist. Biometric `evaluatePolicy` is
only a UI gate. Anyone with file/backup/forensic access to the device recovers
the vault. Defeats zero-knowledge entirely on iOS.
*Fix:* real Keychain storage (`SecItemAdd`/`SecItemCopyMatching`) with
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` + `SecAccessControl`
(`.biometryCurrentSet` / Secure Enclave).

**C2 — Browser extension leaks credentials to untrusted pages**
- Content script matches `http://*/*` and `https://*/*` (`extension/manifest.json`)
  and autofills with a scheme-less, `www`-stripped hostname match
  (`background.ts` `getDomain`). The cleartext password is pushed into the page's
  DOM/closure *before* the user clicks (`content.ts` `createDropdown`/
  `fillCredentials`).
- `background.ts handleMessage` does **no `sender` validation** and trusts the
  message-supplied `url` rather than `sender.tab.url`, so a content script on
  `evil.com` can request `bank.com` credentials and receive them in cleartext.
*Fix:* validate `sender`, derive target from `sender.tab.url`, require explicit
user gesture before exposing secrets, render UI in an isolated frame/shadow root,
enforce scheme + exact-origin matching.

### 🟠 High

**H1 — Web auto-lock is never wired up.** `web/src/hooks/useAutoLock.ts` is
complete but imported nowhere, and `VaultContext.lock()` has no caller. The vault
key lives in memory for the entire tab session — contradicts the README's
"auto-lock after 5 min."

**H2 — Extension KDF mismatch.** `extension/src/lib/argon2.ts` hardcodes
`t=4, m=65536, p=4` and never fetches per-user params — both weaker than and
incompatible with the core's `t=3, m=98304`, so it derives a *different* KEK
(interop/unlock breakage) at a lower work factor.

**H3 — Extension storage defeats its own wrapping.** The wrapping-key *seed* is
stored next to the wrapped vault key in `chrome.storage.session` (`storage.ts`) —
anyone reading that storage reconstructs the key. The refresh token sits in
`chrome.storage.local` (on disk, JS-readable).

**H4 — No TLS certificate pinning on mobile** (`SecureVaultApi.kt`). A
user-installed/corporate root CA can MITM tokens, ciphertext, and tamper with
`kdf-config` responses — expected hardening for a password manager.

**H5 — Android cache leaks metadata.** `VaultEntryEntity` stores `title`,
`username`, `url` in **plaintext** columns (only `password`/`notes`
field-encrypted). The SQLCipher passphrase (`DatabaseKeyManager`) is in
EncryptedSharedPreferences with no `setUserAuthenticationRequired`, so credential
metadata is recoverable on a compromised/rooted device.

### 🟡 Medium

**M1 — User enumeration.** `prelogin` returns a **fresh random salt on every
call** for non-existent emails but a *stable* salt for real users → two calls
reveal existence. Compounded by `register` returning the unmasked
`"An account with this email already exists"` (slips past
`GlobalExceptionHandler`'s mask list).

**M2 — X-Forwarded-For spoofing.** With `APP_PROXY_TRUSTED=true` (set in prod
compose), `ClientIpResolver` takes `XFF.split(",")[0]` — the leftmost,
client-controlled value. An attacker rotates it to bypass per-IP rate limiting
and forge audit-log IPs. Use the rightmost trusted hop.

**M3 — CSP coverage gap & extractable key.** CSP exists only in nginx/
`SecurityHeadersFilter`; `web/index.html` has no `<meta>` CSP, so
`vite dev/preview`, CDN, or static hosting deployments run with **no CSP**. The
access token (in-memory) and the vault key (imported `extractable:true`) are then
fully exfiltratable by any XSS. The CSP also doesn't list the Google Fonts
origins it loads (inconsistency).

**M4 — Prod profile likely inactive.** Neither `Dockerfile` nor
`docker-compose.prod.yaml` sets `SPRING_PROFILES_ACTIVE=prod`, so
`application-prod.properties` and the HSTS block in `SecurityConfig` (guarded by
`isProd`) never apply — HSTS depends entirely on the external proxy.

**M5 — Dev endpoints in release builds.** iOS DI hardcodes
`http://localhost:8080`; Android `network_security_config.xml` ships cleartext
exceptions for `localhost` / `10.0.2.2`.

**M6 — TOTP replay window.** `verifyCode` doesn't mark a code one-time-use, so a
captured TOTP is replayable for its ~30–90s validity.

### 🟢 Low / Info

- **PII in logs:** full emails logged at INFO across register/login/2FA; a
  `"LOGIN_DEBUG: userExists=..."` line leaks account existence to server logs.
- **ProGuard `-keep class com.securevault.mobile.** { *; }`** disables all
  obfuscation for the security-sensitive app.
- **iOS has no auto-lock timer**; decrypted key stays in memory until explicit
  clear.
- **KDF floor too low:** registration allows `kdfMemory=8192` (8 MB), letting a
  client self-weaken below the 96 MB default.
- Client-side JWT parsed without signature verification for UI display
  (spoofable label only).
- `changePassword` returns "Password has been used recently" (history
  disclosure).
- JS can't truly zeroize key material (best-effort nulling only) — inherent.

---

## Priorities

1. **C1 (iOS plaintext storage)** and **C2 (extension credential leak)** — break
   the security model; should block any real deployment of those two clients.
2. **H1 (wire up auto-lock)** and **H4 (cert pinning)** — high-value, low-effort.
3. **H2 / H3** — the extension's crypto/storage need a rethink to match the web
   app's cookie + correct-KDF model.
4. **M1 / M2** — straightforward backend fixes (deterministic prelogin salt;
   rightmost-hop XFF parsing).

The backend and Rust core are in good shape. The extension and iOS client are
where the actual risk concentrates.
