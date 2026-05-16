# Web Frontend — Status

## Stack
- **Framework:** React 19 + TypeScript + Vite 8
- **Styling:** Tailwind CSS v4
- **HTTP:** Fetch API (custom wrapper with JWT auto-refresh)
- **Forms:** React Hook Form + Zod
- **Crypto:** `hash-wasm` (Argon2id Wasm) + Web Crypto API (AES-256-GCM)
- **2FA QR:** `qrcode`
- **Deploy:** Docker (multi-stage) + nginx (alpine)

## Crypto Module

| Layer | Algorithm | Parameters |
|-------|-----------|------------|
| KEK Derivation | Argon2id | iter=3, mem=65536KB, par=4, salt=16B, out=32B |
| Vault Key Wrap/Unwrap | AES-256-GCM | key=KEK(32B), iv=12B, tag=128bit |
| Entry Encrypt/Decrypt | AES-256-GCM | key=VaultKey(32B), iv=12B, tag=128bit |
| Encryption Version | 2 | from AuthResponse |

## Project Structure

```
web/
├── .env.example
├── .dockerignore
├── Dockerfile              # Multi-stage (node:22 build → nginx:alpine)
├── nginx.conf              # CSP headers + /api/ proxy to app:8080
├── vite.config.ts
└── src/
    ├── main.tsx
    ├── App.tsx              # Routes: /login, /register, /vault, /settings
    ├── index.css
    ├── api/
    │   ├── client.ts        # fetch wrapper with JWT + refresh interceptor
    │   ├── auth.ts          # login, register, refresh, logout, changePassword
    │   ├── vault.ts         # vault CRUD
    │   ├── twofa.ts         # 2FA endpoints
    │   ├── audit.ts         # audit log
    │   └── devices.ts       # device management
    ├── crypto/
    │   ├── argon2.ts        # Argon2id Wasm wrapper
    │   ├── vaultKey.ts      # derive KEK, wrap/unwrap vault key
    │   ├── entries.ts       # AES-GCM encrypt/decrypt vault entries
    │   ├── generator.ts     # random password generator
    │   ├── strength.ts      # password strength (0-10, min 4)
    │   └── util.ts          # base64 helpers + random bytes
    ├── context/
    │   ├── AuthContext.tsx   # JWT, user, login/logout, master password ref
    │   └── VaultContext.tsx  # vault key + entries cache + CRUD
    ├── hooks/
    │   └── useAutoLock.ts   # idle timer → wipe vault key
    ├── components/
    │   ├── Layout.tsx        # sidebar + mobile hamburger
    │   ├── ProtectedRoute.tsx
    │   ├── PasswordStrength.tsx
    │   ├── CopyButton.tsx    # 30s auto-clear
    │   ├── EmptyState.tsx
    │   ├── LoadingSpinner.tsx
    │   └── ErrorBoundary.tsx
    └── pages/
        ├── LoginPage.tsx
        ├── RegisterPage.tsx
        ├── VaultPage.tsx        # list + search + inline unlock
        ├── VaultEntryPage.tsx   # view/edit/delete
        ├── VaultEntryForm.tsx   # add/edit + password generator
        └── SettingsPage.tsx     # security, 2FA, devices, audit tabs
```

## Implementation Status

### Phase 1 — Scaffold + Auth ✅
- Vite + React + TS + Tailwind scaffold
- `api/client.ts` — fetch wrapper with JWT interceptor + 401 auto-refresh
- `api/auth.ts` — login, register, refresh, logout
- `context/AuthContext.tsx` — tokens, user state, master password ref
- `components/ProtectedRoute.tsx` — redirect to login if unauthenticated
- `pages/LoginPage.tsx` — email + password form
- `pages/RegisterPage.tsx` — email + password + device setup form

### Phase 2 — Crypto ✅
- `crypto/argon2.ts` — `hash-wasm` argon2id wrapper
- `crypto/vaultKey.ts` — KEK derivation + vault key wrap/unwrap (AES-GCM)
- `crypto/entries.ts` — entry encrypt/decrypt (AES-GCM)
- `crypto/generator.ts` — secure password generator
- `crypto/strength.ts` — password strength (0-10 scale)
- `context/VaultContext.tsx` — in-memory vault key + entries cache
- Auto-unlock on login (no separate unlock page)
- Inline unlock form on VaultPage for page-reload case
- `hooks/useAutoLock.ts` — idle timer, wipe vault key

### Phase 3 — Vault CRUD ✅
- `api/vault.ts` — vault CRUD API calls
- `pages/VaultPage.tsx` — list entries, search/filter, decrypt on display
- `pages/VaultEntryForm.tsx` — add entry (encrypt → POST)
- `pages/VaultEntryPage.tsx` — view/edit entry (decrypt → display → encrypt → PUT)
- `components/EmptyState.tsx` — empty vault state

### Phase 4 — Settings ✅
- `api/twofa.ts` — 2FA API calls
- `api/devices.ts` — device API calls
- `api/audit.ts` — audit log API
- `pages/SettingsPage.tsx` — tabs: security, 2FA, devices, audit
- Change password flow — re-encrypt vault key client-side
- 2FA setup — display QR code, enable/disable
- Device management — list/remove
- Audit log viewer — paginated table

### Phase 5 — Polish ✅
- `components/PasswordStrength.tsx` — visual strength bar
- `components/CopyButton.tsx` — copy with 30s auto-clear
- `components/LoadingSpinner.tsx` — shared spinner
- `components/ErrorBoundary.tsx` — catch and display errors
- Responsive sidebar with mobile hamburger + overlay
- Password generator in VaultEntryForm

### Phase 6 — Deploy ✅
- CSP headers via nginx.conf
- Multi-stage Dockerfile (node:22 build → nginx:alpine serve)
- `.dockerignore`
- `docker-compose.yaml` updated with web service (Traefik labels)
- Vite production build config
- End-to-end tested against vault.tanay.pro

## API Endpoints Consumed

```
POST   /api/v1/auth/login
POST   /api/v1/auth/register
POST   /api/v1/auth/refresh
POST   /api/v1/auth/logout
POST   /api/v1/auth/change-password
GET    /api/v1/vault
POST   /api/v1/vault
GET    /api/v1/vault/:id
PUT    /api/v1/vault/:id
DELETE /api/v1/vault/:id
GET    /api/v1/2fa/setup
POST   /api/v1/2fa/enable
POST   /api/v1/2fa/disable
GET    /api/v1/2fa/status
GET    /api/v1/devices
DELETE /api/v1/devices/:id
GET    /api/v1/audit
```

## Security Notes

- Vault key lives only in `useRef()` — never persisted to disk/DOM
- Auto-lock wipes vault key after N minutes of inactivity
- Session tokens (JWT) stored in localStorage
- Clipboard auto-clears after 30s
- All encryption/decryption client-side — zero-knowledge preserved
- HTTPS required (Web Crypto API requires secure context)
- CSP headers set by nginx (script-src, connect-src, etc.)
- nginx proxies `/api/` to backend — no CORS in production
