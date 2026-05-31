# SecureVault — Password Manager

A production-ready, zero-knowledge password manager with a shared Rust crypto-core, Spring Boot backend, React web app, and Kotlin Multiplatform mobile app (Android + iOS).

[![Security Audit](docs/SECURITY_AUDIT.md)](docs/SECURITY_AUDIT.md)

## Security Posture

**Core architecture: Strong.** The zero-knowledge crypto design (Argon2id → HKDF-Expand → AES-256-GCM key wrapping) is textbook-correct. Backend is well-hardened with server-side pepper, proper JWTs, rate limiting, sudo mode, and audit logging.

**Soft spots:** iOS stores vault key in plaintext NSUserDefaults (C1), browser extension has credential leak via unvalidated `sender` (C2), auto-lock never wired in web (H1), no certificate pinning on mobile (H4).

See [full security audit](docs/SECURITY_AUDIT.md) for details.

## Features

### Zero-Knowledge Cryptography
- **Single Argon2id call + HKDF-Expand (RFC 5869)** — matches Bitwarden's architecture
- **AES-256-GCM vault key wrapping** — vault key encrypted with KEK, server never sees plaintext
- **Server-side HMAC-SHA256 pepper** — DB-only breach can't crack passwords
- **Random 16-byte salt** — not email-based (Bitwarden's weakness)
- **Golden test vectors** verified across Rust/WASM/JNI/C-FFI — all platforms derive identical keys

### Authentication & Session Security
- **2FA (TOTP)** — secret encrypted at rest (AES-GCM)
- **Account lockout** — 5 failed attempts / 15 min
- **Per-endpoint rate limiting** — distributed via Redis (login, register, sudo, audit, KDF config)
- **Per-email register limit** — 3 attempts/hr
- **Step-up "sudo" mode** — single-use 5-min token gates destructive operations
- **JWT with pwdUpdatedAt claim** — instant session invalidation on password change
- **Refresh token rotation + reuse detection** — stolen token revokes entire family
- **HttpOnly/Secure/SameSite=Strict cookies** for web refresh tokens

### Web App (React)
- Client-side Argon2id + AES-256-GCM via Rust WASM (`crypto-core`)
- Password generator with configurable rules
- Password strength meter
- Cross-tab vault lock on password change

### Mobile App (KMP)
- Shared Kotlin across Android & iOS
- Jetpack Compose UI
- Biometric unlock (Android Keystore / iOS Keychain — iOS TBD)
- Background KDF upgrade on unlock (picks up server KDF defaults)
- Offline-capable with encrypted local cache

### Backend
- **KDF defaults configurable via env vars** (`KDF_ITERATIONS`, `KDF_MEMORY`, `KDF_PARALLELISM`)
- **`GET /auth/kdf-config`** endpoint — clients fetch current server defaults
- **Sudo gated** — change-password, delete-account, upgrade-kdf, delete-all-entries
- **Audit logging** — KDF upgrades, account deletion tracked
- **HIBP breach check** via k-anonymity (registration + password change)
- **Password history** — prevents reuse (last 5)
- **Device management** — register, list, remove devices
- **Security headers** — CSP, HSTS (prod profile), X-Frame-Options, etc.
- **Swagger/OpenAPI** — disabled by default, gated by env var

## Project Structure

```
Password-Manager/
├── crypto-core/                    # Shared Rust crypto core
│   └── src/                        #   lib.rs, kdf.rs, aead.rs,
│   │                               #   wasm.rs, jni_bridge.rs, c_ffi.rs
│   └── tests/                      #   Integration tests (golden vectors)
│   └── securevault_crypto_core.h   #   C header for iOS
├── src/                            # Spring Boot backend
│   └── main/java/com/securevault/
│       ├── controller/             #   REST API endpoints
│       ├── service/                #   Business logic
│       ├── repository/             #   Data access
│       ├── entity/                 #   JPA entities
│       ├── dto/                    #   Request/response DTOs
│       ├── security/               #   JWT, sudo, rate limiter, challenge store
│       ├── config/                 #   Security, CORS, rate limiting, filters, Swagger
│       └── util/                   #   Client IP resolver, user utils
├── web/                            # React web app (Vite)
│   ├── src/
│   │   ├── api/                    #   API client + endpoint modules
│   │   ├── components/             #   Shared UI components
│   │   ├── context/                #   Auth + Vault context
│   │   ├── crypto/                 #   WASM wrapper (Argon2, AES-GCM)
│   │   ├── hooks/                  #   useAutoLock
│   │   ├── pages/                  #   Login, Register, Vault, Settings
│   │   └── App.tsx                 #   Router setup
│   └── extension/                  # Browser extension (prototype)
├── mobile/                         # KMP mobile app
│   └── app/
│       ├── commonMain/             #   Shared code (Ktor, crypto expect, UI)
│       ├── androidMain/            #   Android: Keystore, Room, SQLCipher
│       └── iosMain/                #   iOS: Keychain stubs (needs C1 fix)
├── docker-compose.yaml             # Local dev
├── docker-compose.prod.yaml        # Production (Dockploy-compatible)
├── docs/                           # Documentation
│   ├── SECURITY_AUDIT.md           #   Full security assessment
│   └── need_to_fix.md              #   162 tracked items (86 fixed, 76 open)
└── test-all.sh                     # One-click cross-platform test suite
```

## Quick Start

### Prerequisites
- **Backend:** Java 17+, Maven 3.9+, PostgreSQL 16, Redis 7+
- **Web:** Node.js 20+
- **Mobile:** Android Studio / Xcode, Android SDK
- **Rust core:** Rust toolchain (for WASM/JNI/iOS builds)

### Build Rust Crypto Core

```bash
cd crypto-core
# Build all targets (run from project root)
./build-mobile.sh         # JNI .so + iOS .a + WASM .wasm
```

### Running Backend

```bash
git clone git@github.com:tanaymondal/Password-Manager.git
cd Password-Manager

# Set required environment variables
export JWT_SECRET="your-secret-key-at-least-32-chars"
export SERVER_HASH_SECRET="your-256-bit-hex-key"
export ENCRYPTION_KEY="your-32-byte-base64-key"
export DB_USERNAME=postgres
export DB_PASSWORD=yourpassword

# Run
mvn spring-boot:run
```

### Running Web App

```bash
cd web
cp .env .env.local        # Set VITE_API_URL=http://localhost:8080/api/v1
npm install
npm run dev               # http://localhost:3000
```

### Using Docker Compose

```bash
# Local dev
docker-compose -f docker-compose.yaml up -d

# Production (VPS with Dockploy)
docker-compose -f docker-compose.prod.yaml up -d
```

### Running Mobile App

```bash
cd mobile
./gradlew installDebug
```

## Environment Variables

### Backend

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_HOST` | Yes | localhost | Database host |
| `DB_PORT` | Yes | 5432 | Database port |
| `DB_NAME` | Yes | securevault | Database name |
| `DB_USERNAME` | Yes | postgres | Database user |
| `DB_PASSWORD` | No | (empty) | Database password |
| `JWT_SECRET` | Yes | - | JWT signing secret (min 32 chars) |
| `SERVER_HASH_SECRET` | Yes | - | HMAC-SHA256 key for server-side pepper (64 hex chars) |
| `ENCRYPTION_KEY` | Yes | - | AES-256 key for TOTP secrets at rest (32 bytes, base64) |
| `REDIS_HOST` | No | localhost | Redis host |
| `REDIS_PASSWORD` | No | (empty) | Redis password |
| `KDF_ITERATIONS` | No | 3 | Argon2id time cost (t) |
| `KDF_MEMORY` | No | 98304 | Argon2id memory cost in KiB (96 MiB) |
| `KDF_PARALLELISM` | No | 4 | Argon2id parallelism (p) |
| `JWT_EXPIRATION` | No | 3600000 | Access token expiry (ms) |
| `JWT_REFRESH_EXPIRATION` | No | 86400000 | Refresh token expiry (ms) |
| `SERVER_PORT` | No | 8080 | Server port |
| `IP_RATE_LIMIT` | No | 20 | Per-IP requests/minute |
| `EMAIL_RATE_LIMIT` | No | 3 | Register attempts/hr per email |
| `APP_PROXY_TRUSTED` | No | false | Trust X-Forwarded-For headers |
| `APP_CORS_ORIGINS` | No | http://localhost:3000 | Allowed CORS origins |
| `APP_CORS_METHODS` | No | GET,POST,PUT,DELETE | Allowed CORS methods |
| `SWAGGER_ENABLED` | No | false | Enable Swagger UI |
| `SSL_ENABLED` | No | false | Enable SSL |
| `SSL_KEYSTORE` | No | - | Keystore path |
| `SSL_KEYSTORE_PASSWORD` | No | - | Keystore password |
| `LOG_LEVEL` | No | INFO | Logging level |

### Web

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VITE_API_URL` | Yes | - | Backend API base URL |

## API Endpoints

### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/auth/prelogin` | No | Get user's salt + KDF params for login |
| POST | `/api/v1/auth/kdf-config` | No (rate-limited) | Get server's current KDF defaults |
| POST | `/api/v1/auth/register` | No (rate-limited) | Register new user |
| POST | `/api/v1/auth/login` | No (rate-limited) | Login (returns JWT + wrapped vault key) |
| POST | `/api/v1/auth/verify-2fa` | No | Verify 2FA TOTP code during login |
| POST | `/api/v1/auth/refresh` | Cookie | Refresh access token |
| POST | `/api/v1/auth/logout` | Cookie | Logout (invalidates refresh token) |
| POST | `/api/v1/auth/sudo` | Bearer | Get sudo token (re-auth) |
| POST | `/api/v1/auth/change-password` | Sudo | Change master password |
| POST | `/api/v1/auth/upgrade-kdf` | Sudo | Upgrade KDF parameters |
| DELETE | `/api/v1/auth/delete-account` | Sudo | Delete account |

### Vault

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/vault` | Bearer | Get all vault entries |
| POST | `/api/v1/vault` | Bearer | Create vault entry (encrypted) |
| GET | `/api/v1/vault/{id}` | Bearer | Get single entry |
| PUT | `/api/v1/vault/{id}` | Bearer | Update entry (encrypted) |
| DELETE | `/api/v1/vault/{id}` | Bearer | Delete entry |

### Devices

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/devices` | Bearer | List registered devices |
| POST | `/api/v1/devices` | Bearer | Register device |
| DELETE | `/api/v1/devices/{id}` | Bearer | Remove device |

### Two-Factor Auth

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/2fa/setup` | Bearer | Get 2FA setup (QR code + secret) |
| POST | `/api/v1/2fa/enable` | Bearer | Enable 2FA |
| POST | `/api/v1/2fa/disable` | Bearer | Disable 2FA |
| GET | `/api/v1/2fa/status` | Bearer | Check 2FA status |

### Other

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/health` | No | Health check |
| GET | `/api/v1/audit` | Bearer | Get audit logs |

## Web Routes

| Path | Page | Description |
|------|------|-------------|
| `/login` | LoginPage | Login with email/password |
| `/register` | RegisterPage | Create account |
| `/vault` | VaultPage | View all entries (requires unlock) |
| `/vault/new` | VaultEntryForm | Create new entry |
| `/vault/:id` | VaultEntryPage | View single entry |
| `/settings` | SettingsPage | Change password, 2FA, devices |

## Security Architecture

### Crypto Chain

```
Master Password
      │
      └── Argon2id(password, salt, t=3, m=96MiB, p=4) ──→ Master Key (32 bytes)
                                                                    │
                                                     ┌──────────────┼──────────────┐
                                                     │              │              │
                                           HKDF-Expand("auth")   HKDF-Expand("kek")
                                                     │              │              │
                                                 Auth Hash         KEK       HKDF-Expand(other)
                                                     │              │
                                          HMAC-SHA256(·, secret)    │
                                                     │              │
                                              Server Hash     AES-256-GCM unwrap
                                                     │              │
                                               Stored in DB     Vault Key (random 256-bit)
                                                                      │
                                                            AES-256-GCM encrypt/decrypt
                                                                      │
                                                            Encrypted Vault Entries
```

- **Single Argon2id call** + HKDF-Expand (RFC 5869) with domain tags for `"auth"` and `"kek"`
- **Random 16-byte salt** (not email-derived — Bitwarden's weakness)
- **Server-side pepper**: `HMAC-SHA256(authHash, SERVER_HASH_SECRET + ":" + salt)` — DB breach alone can't crack passwords
- **All crypto primitives** share the same Rust implementation (WASM for web, JNI for Android, C-FFI for iOS) — verified via cross-platform golden test vectors

### Registration Flow
1. Client fetches KDF defaults from `GET /auth/kdf-config`
2. Client generates random 16-byte salt
3. Client derives `masterKey = Argon2id(password, salt)`
4. Client derives `authHash = HKDF-Expand(masterKey, "auth")` and `KEK = HKDF-Expand(masterKey, "kek")`
5. Client sends `(email, authHash, salt, kdfParams, publicKey)` to server
6. Server computes `serverHash = HMAC-SHA256(authHash, SECRET + ":" + salt)` and stores it
7. Server generates random vault key, wraps it with KEK, stores wrapped key
8. Returns JWT tokens + wrapped vault key to client
9. Client unwraps vault key with KEK, caches in memory

### Login Flow
1. Client calls `prelogin` with email → gets salt + KDF params
2. Client derives authHash as in registration
3. Server verifies `HMAC-SHA256(authHash, SECRET + ":" + salt)` matches stored hash
4. Returns JWT tokens + wrapped vault key
5. Client derives KEK, unwraps vault key

### Password Change
1. Client fetches all vault entries (decrypts with current vault key)
2. Generates **new vault key** and re-encrypts every entry
3. Derives new KEK from new password + new salt
4. Wraps new vault key with new KEK
5. Sends re-encrypted entries + new wrapped vault key to server
6. Server deletes all refresh tokens (forces other sessions to re-login)
7. Issues new JWT tokens with updated `pwdUpdatedAt` claim
8. Old access tokens rejected immediately (claim mismatch)

## Tech Stack

### Rust Crypto Core
- **Language:** Rust (compiled to WASM, JNI .so, C-FFI .a/.h)
- **KDF:** `argon2` crate (Argon2id)
- **Cipher:** `aes-gcm` crate (AES-256-GCM)
- **Key derivation:** `hkdf` crate (RFC 5869)

### Backend
- **Framework:** Spring Boot 3.2
- **Language:** Java 17
- **Database:** PostgreSQL 16 with Flyway migrations
- **Cache:** Redis 7 (rate limiting, token denylist, challenge store)
- **ORM:** Spring Data JPA / Hibernate
- **Auth:** JWT (jjwt 0.12.3) + HMAC-SHA256 server pepper
- **2FA:** TOTP (samstevens/totp)
- **API Docs:** SpringDoc OpenAPI (disabled by default)

### Web App
- **Framework:** React 19 + Vite 8
- **Language:** TypeScript 6
- **Styling:** Tailwind CSS 4
- **Crypto:** Rust WASM (Argon2id + AES-256-GCM), Web Crypto API (AES-GCM fallback)
- **Forms:** React Hook Form + Zod 4
- **Routing:** React Router 7

### Mobile App
- **Language:** Kotlin (KMP — shared across Android & iOS)
- **UI:** Jetpack Compose
- **DI:** Koin
- **Networking:** Ktor
- **Architecture:** Clean Architecture + MVVM
- **Crypto:** JNI (`crypto-core.so` on Android), C-FFI (`securevault_crypto_core.a` on iOS)

## Testing

```bash
# One-click cross-platform test suite
./test-all.sh

# Or run individually:
mvn -q test                          # Backend
cd web && npm run build && npm test  # Web
cargo test --lib -q                  # Rust core
cd mobile && ./gradlew test          # Mobile (Android unit tests)
```

## Development

### Pre-push Checklist
- `mvn -q test` — backend tests pass
- `cd web && npm run build && npm test` — web builds + tests pass
- `cd crypto-core && cargo test --lib -q` — Rust tests pass
- `cd mobile && ./gradlew :app:testDebugUnitTest` — Android unit tests pass

## License

MIT License
