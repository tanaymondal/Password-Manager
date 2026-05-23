# SecureVault - Password Manager

A production-ready, zero-knowledge password manager with Spring Boot backend, React web app, and Kotlin Multiplatform mobile app.

## Features

### Security
- **Zero-knowledge architecture** — server never sees plaintext passwords
- **Argon2id** password hashing for authentication (separate salt from encryption)
- **AES-256-GCM vault key wrapping** — vault key encrypted with key derived from master password
- **Vault key rotation** — change password re-encrypts all entries with a new vault key
- **Immediate session invalidation** — `pwdUpdatedAt` JWT claim rejects old tokens instantly
- **Two-factor authentication** (TOTP/Google Authenticator)
- **Account lockout** after 5 failed login attempts (15 min lockout)
- **Password history** — prevents password reuse (last 5)
- **HaveIBeenPwned breach check** on registration and password change
- **Rate limiting** — 60 requests/minute
- **Cross-tab detection** — detects password changed in another tab

### Web App (React)
- Client-side AES-256-GCM encryption/decryption
- Password generator with configurable rules (length, character types, exclude ambiguous)
- Client-side password strength meter (0–10 scoring)
- Session management with automatic token refresh
- Auto-lock vault after inactivity (default 5 min)
- Cross-tab vault lock on password change

### Mobile App (Android & iOS)
- Kotlin Multiplatform — shared code between Android and iOS
- Jetpack Compose UI
- Offline-capable with local caching
- Encrypted local storage via Android Keystore

## Project Structure

```
Password-Manager/
├── src/                           # Spring Boot Backend
│   └── main/java/com/securevault/
│       ├── controller/            # REST API endpoints
│       ├── service/               # Business logic
│       ├── repository/            # Data access
│       ├── entity/                # JPA entities
│       ├── dto/                   # Request/Response DTOs
│       ├── security/              # JWT filter, token provider, auth provider
│       ├── config/                # Security, CORS, rate limiting, Swagger
│       └── util/                  # Input sanitizer, user utils
├── web/                           # React Web App (Vite)
│   └── src/
│       ├── api/                   # API client + endpoint modules
│       ├── components/            # Shared UI components
│       ├── context/               # Auth + Vault context
│       ├── crypto/                # Argon2, AES-GCM, strength, generator
│       ├── hooks/                 # useAutoLock
│       ├── pages/                 # Login, Register, Vault, Settings, etc.
│       ├── App.tsx                # Router setup
│       └── main.tsx               # Entry point
├── mobile/                        # Kotlin Multiplatform Mobile App
│   └── app/
│       ├── androidMain/           # Android-specific code
│       ├── commonMain/            # Shared code
│       └── iosMain/               # iOS-specific code
├── docker-compose.yaml            # Docker deployment
└── README.md
```

## Quick Start

### Prerequisites
- **Backend:** Java 17+, Maven 3.9+, PostgreSQL 16+
- **Web:** Node.js 20+
- **Mobile:** Android Studio / Xcode, Android SDK

### Running Backend

```bash
git clone git@github.com:tanaymondal/Password-Manager.git
cd Password-Manager

# Create database
createdb securevault

# Set environment variables
export JWT_SECRET="your-secret-key-at-least-32-chars"
export DB_USERNAME=postgres
export DB_PASSWORD=yourpassword

# Run
mvn spring-boot:run
```

### Running Web App

```bash
cd web
cp .env .env.local        # Change VITE_API_URL to http://localhost:8080/api/v1
npm install
npm run dev               # Opens at http://localhost:3000
```

### Using Docker Compose

```bash
docker-compose -f docker-compose.yaml up -d
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
| `DB_USERNAME` | Yes | tanay | Database user |
| `DB_PASSWORD` | No | (empty) | Database password |
| `JWT_SECRET` | Yes | - | JWT signing secret (min 32 chars) |
| `JWT_EXPIRATION` | No | 3600000 | Access token expiry (ms) |
| `JWT_REFRESH_EXPIRATION` | No | 86400000 | Refresh token expiry (ms) |
| `SERVER_PORT` | No | 8080 | Server port |
| `RATE_LIMIT` | No | 60 | Requests per minute |
| `SWAGGER_ENABLED` | No | false | Enable Swagger UI |
| `SSL_ENABLED` | No | false | Enable SSL |
| `SSL_KEYSTORE` | No | - | Keystore path (SSL) |
| `SSL_KEYSTORE_PASSWORD` | No | - | Keystore password |
| `REDIS_HOST` | No | localhost | Redis host |
| `LOG_LEVEL` | No | INFO | Logging level |

### Web
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VITE_API_URL` | Yes | - | Backend API base URL |

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login (returns JWT + wrapped vault key) |
| POST | `/api/v1/auth/verify-2fa` | Verify 2FA TOTP code |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Logout (invalidates refresh token) |
| POST | `/api/v1/auth/change-password` | Change master password |

### Vault
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/vault` | Get all vault entries |
| POST | `/api/v1/vault` | Create vault entry (encrypted) |
| GET | `/api/v1/vault/{id}` | Get single entry |
| PUT | `/api/v1/vault/{id}` | Update entry (encrypted) |
| DELETE | `/api/v1/vault/{id}` | Delete entry |

### Devices
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/devices` | List registered devices |
| POST | `/api/v1/devices` | Register device |
| DELETE | `/api/v1/devices/{id}` | Remove device |

### Two-Factor Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/2fa/setup` | Get 2FA setup (QR code + secret) |
| POST | `/api/v1/2fa/enable` | Enable 2FA |
| POST | `/api/v1/2fa/disable` | Disable 2FA |
| GET | `/api/v1/2fa/status` | Check 2FA status |

### Other
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/audit` | Get audit logs |

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

### Encryption Model

```
Master Password
      │
      ├── Argon2id(auth_salt) ──→ Password Hash (stored, for server verification)
      │
      └── Argon2id(encryption_salt) ──→ KEK (Key Encryption Key)
                                              │
                                    AES-256-GCM unwrap
                                              │
                                            Vault Key (random 256-bit)
                                              │
                                    AES-256-GCM encrypt/decrypt
                                              │
                                      Encrypted Entries
```

### Registration
1. Server generates two random salts (auth + encryption)
2. Hashes password with auth salt → stores hash for verification
3. Generates a random vault key, wraps it with KEK derived from master password + encryption salt
4. Returns JWT tokens + wrapped vault key + encryption salt to client
5. Client unwraps vault key and caches it in memory

### Login
1. Server verifies password hash
2. Returns JWT tokens + wrapped vault key + encryption salt
3. Client derives KEK from password, unwraps vault key, caches in memory

### Password Change
1. Client fetches all vault entries
2. Generates a **new vault key** and re-encrypts every entry
3. Derives new KEK from new password + new encryption salt
4. Wraps new vault key with new KEK
5. Sends re-encrypted entries + new wrapped vault key to server
6. Server deletes all refresh tokens (forces other sessions to re-login)
7. Issues new JWT tokens tagged with current `passwordUpdatedAt`
8. Old access tokens rejected immediately (pwdUpdatedAt claim mismatch)

## Database Migrations (Flyway)

| Migration | Description |
|-----------|-------------|
| `V1__initial_schema.sql` | Users, vault entries, devices, audit logs |
| `V2__add_security_enhancements.sql` | Lockout, 2FA, password history |
| `V3__add_vault_key_management.sql` | Wrapped vault key, encryption salt |
| `V4__add_password_salt_to_history.sql` | Track salt per password history entry |
| `V5__rename_token_to_token_hash.sql` | Rename token column for clarity |

## Tech Stack

### Backend
- **Framework:** Spring Boot 3.2
- **Language:** Java 17
- **Database:** PostgreSQL 16 with Flyway migrations
- **ORM:** Spring Data JPA / Hibernate
- **Authentication:** JWT (jjwt 0.12.3) with access/refresh tokens
- **Password Hashing:** Argon2id (BouncyCastle)
- **2FA:** TOTP (samstevens/totp)
- **API Docs:** SpringDoc OpenAPI (disabled by default)

### Web App
- **Framework:** React 19.2 + Vite 8
- **Language:** TypeScript 6
- **Styling:** Tailwind CSS 4.3
- **Crypto:** hash-wasm (Argon2id), Web Crypto API (AES-256-GCM)
- **Forms:** React Hook Form + Zod 4
- **Routing:** React Router 7.15
- **Linting:** ESLint 10 + typescript-eslint

### Mobile App
- **Language:** Kotlin
- **Platform:** Android & iOS (Multiplatform)
- **UI Framework:** Jetpack Compose
- **DI:** Koin
- **Networking:** Ktor
- **Architecture:** Clean Architecture + MVVM

## License

MIT License
