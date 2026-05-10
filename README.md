# SecureVault - Password Manager

A production-ready, security-focused password manager with Spring Boot backend and Kotlin Multiplatform mobile app.

## Features

### Security
- **Argon2id** password hashing for authentication
- **Separate encryption key derivation** using unique salt per user
- **End-to-end encryption** - server never sees plaintext passwords
- **Client-side AES-256-GCM encryption** using PBKDF2
- **EncryptedSharedPreferences** for secure session storage
- **JWT authentication** with access/refresh tokens
- **Two-factor authentication** (TOTP/Google Authenticator)
- **Account lockout** after 5 failed login attempts (15 min lockout)
- **Password history** - prevents password reuse (stores last 5)
- **Rate limiting** - 60 requests/minute

### Mobile App (Android & iOS)
- **Kotlin Multiplatform** - Shared code between Android and iOS
- **Jetpack Compose** UI for Android
- **Koin** for dependency injection
- **Ktor** for networking
- **Clean Architecture** with MVVM pattern
- **Offline-capable** with local caching
- **Encrypted local storage** via Android Keystore

## Project Structure

```
Password-Manager/
├── src/                    # Spring Boot Backend
│   └── main/java/com/securevault/
│       ├── controller/     # REST API endpoints
│       ├── service/       # Business logic
│       ├── repository/    # Data access
│       ├── entity/        # JPA entities
│       ├── dto/           # Request/Response DTOs
│       ├── config/        # Security & app config
│       └── util/          # Utilities
├── mobile/                 # Kotlin Multiplatform Mobile App
│   ├── app/
│   │   ├── androidMain/   # Android-specific code
│   │   ├── commonMain/    # Shared code
│   │   └── iosMain/       # iOS-specific code
│   └── gradle/            # Gradle wrapper
├── docker-compose.yml     # Docker deployment
└── README.md
```

## Quick Start

### Prerequisites
- **Backend:** Java 17+, Maven 3.9+, PostgreSQL 16+
- **Mobile:** Android Studio / Xcode, Android SDK

### Running Backend

```bash
# Clone the repository
git clone git@github.com:tanaymondal/Password-Manager.git
cd Password-Manager

# Create database
createdb securevault

# Run the application
mvn spring-boot:run

# Or build and run
mvn clean package -DskipTests
java -jar target/securevault-1.0.0.jar
```

### Running Mobile App (Android)

```bash
cd mobile
./gradlew installDebug
```

**Note:** For Android emulator, the app connects to `http://10.0.2.2:8080` (localhost).

### Using Docker Compose

```bash
docker-compose up -d
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|--------------|
| `DB_HOST` | Yes | localhost | Database host |
| `DB_PORT` | Yes | 5432 | Database port |
| `DB_NAME` | Yes | securevault | Database name |
| `DB_USERNAME` | Yes | - | Database user |
| `DB_PASSWORD` | Yes | - | Database password |
| `JWT_SECRET` | Yes | - | JWT signing secret (min 32 chars) |
| `SERVER_PORT` | No | 8080 | Server port |
| `SWAGGER_ENABLED` | No | false | Enable Swagger UI |

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login (returns JWT + encryption salt) |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Logout |
| POST | `/api/v1/auth/change-password` | Change password |

### Vault
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/vault` | Get all vault entries |
| POST | `/api/v1/vault` | Create vault entry (encrypted) |
| GET | `/api/v1/vault/{id}` | Get single entry |
| PUT | `/api/v1/vault/{id}` | Update entry (encrypted) |
| DELETE | `/api/v1/vault/{id}` | Delete entry |
| DELETE | `/api/v1/vault` | Delete all entries |

### Devices
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/devices` | List devices |
| POST | `/api/v1/devices` | Register device |
| DELETE | `/api/v1/devices/{id}` | Remove device |

### Two-Factor Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/2fa/setup` | Get 2FA QR code |
| POST | `/api/v1/2fa/enable` | Enable 2FA |
| POST | `/api/v1/2fa/disable` | Disable 2FA |
| GET | `/api/v1/2fa/status` | Check 2FA status |

### Other
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/audit` | Get audit logs |

## Security Flow

### Registration
1. Client sends email + password
2. Server generates two salts (auth + encryption)
3. Server stores: `password_hash = Argon2id(password, auth_salt)`
4. Server returns: JWT + `encryption_salt`

### Login
1. Client sends email + password
2. Server verifies: `Argon2id(password, stored_salt) == stored_hash`
3. Server returns: JWT + `encryption_salt`

### Client-Side Encryption
1. Client derives: `encryption_key = PBKDF2(master_password, encryption_salt)`
2. Client encrypts: `ciphertext = AES-256-GCM(plaintext, encryption_key)`
3. Client sends: `ciphertext + iv` to server
4. Server stores encrypted data (never sees plaintext)

## Tech Stack

### Backend
- **Framework:** Spring Boot 3.2
- **Language:** Java 17
- **Database:** PostgreSQL 16
- **ORM:** Spring Data JPA / Hibernate
- **Authentication:** JWT (jjwt)
- **Password Hashing:** BouncyCastle (Argon2id)
- **2FA:** TOTP (samstevens/totp)
- **API Docs:** SpringDoc OpenAPI

### Mobile App
- **Language:** Kotlin
- **Platform:** Android & iOS (Multiplatform)
- **UI Framework:** Jetpack Compose
- **DI:** Koin
- **Networking:** Ktor
- **Architecture:** Clean Architecture + MVVM
- **Encryption:** AES-256-GCM with PBKDF2
- **Secure Storage:** Android EncryptedSharedPreferences

## Database Schema

### Users Table
- id, email, password_hash, password_salt, encryption_salt
- two_factor_enabled, two_factor_secret
- failed_login_attempts, locked_until
- password_history (last 5 passwords)

### Vault Entries Table
- id, user_id, encrypted_data, iv, version

### Devices Table
- id, user_id, device_name, device_id, public_key

### Audit Logs Table
- id, user_id, action, ip_address, user_agent, details

## License

MIT License
