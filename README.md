# SecureVault - Password Manager Backend

A production-ready, security-focused password manager backend built with Spring Boot.

## Features

### Security
- **Argon2id** password hashing for authentication
- **Separate encryption key derivation** using unique salt per user
- **End-to-end encryption** - server never sees plaintext passwords
- **JWT authentication** with access/refresh tokens
- **Two-factor authentication** (TOTP/Google Authenticator)
- **Account lockout** after 5 failed login attempts (15 min lockout)
- **Password history** - prevents password reuse (stores last 5)
- **Rate limiting** - 60 requests/minute (30 in production)
- **Login rate limiter** - blocks brute force attacks
- **Security headers** - HSTS, X-Frame-Options, CSP

### Architecture
- **Client-side encryption** - AES-256-GCM encryption done on client
- **Stateless API** - JWT based authentication
- **PostgreSQL** database with Flyway migrations
- **OpenAPI/Swagger** documentation

## Quick Start

### Prerequisites
- Java 17+
- Maven 3.9+
- PostgreSQL 16+
- (Optional) Redis for caching

### Running Locally

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
| `LOG_LEVEL` | No | INFO | Logging level |

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
| POST | `/api/v1/vault` | Create vault entry |
| GET | `/api/v1/vault/{id}` | Get single entry |
| PUT | `/api/v1/vault/{id}` | Update entry |
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

### Encryption (Client-Side)
1. Client derives: `encryption_key = Argon2id(master_password, encryption_salt)`
2. Client encrypts: `ciphertext = AES-256-GCM(plaintext, encryption_key)`
3. Client sends: `ciphertext + iv` to server
4. Server stores encrypted data (never sees plaintext)

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

## Production Deployment

```bash
# Generate JWT secret
openssl rand -base64 32

# Set environment variables
export JWT_SECRET="your-generated-secret"
export DB_PASSWORD="strong-db-password"
export SWAGGER_ENABLED=false

# Run with production profile
java -jar target/securevault-1.0.0.jar --spring.profiles.active=prod
```

### Required Configuration
- SSL/TLS termination (nginx)
- Database encryption at rest
- Strong JWT secret (min 32 chars)
- Disable Swagger in production

## Tech Stack

- **Framework:** Spring Boot 3.2
- **Language:** Java 17
- **Database:** PostgreSQL 16
- **ORM:** Spring Data JPA / Hibernate
- **Authentication:** JWT (jjwt)
- **Password Hashing:** BouncyCastle (Argon2id)
- **2FA:** TOTP (samstevens/totp)
- **API Docs:** SpringDoc OpenAPI

## License

MIT License