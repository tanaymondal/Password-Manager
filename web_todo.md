# Web Frontend — Implementation Plan

## Stack
- **Framework:** React 18 + TypeScript
- **Build:** Vite
- **Styling:** Tailwind CSS v4
- **HTTP:** Fetch API (custom wrapper with JWT auto-refresh)
- **Forms:** React Hook Form + Zod
- **Crypto:** `hash-wasm` (Argon2id Wasm) + Web Crypto API (AES-256-GCM)
- **2FA QR:** `qrcode`

## Crypto Module (replaces mobile's `AndroidEntryEncryptor`)

| Layer | Algorithm | Parameters |
|-------|-----------|------------|
| KEK Derivation | Argon2id | iter=3, mem=65536KB, par=4, salt=16B, out=32B |
| Vault Key Wrap/Unwrap | AES-256-GCM | key=KEK(32B), iv=12B, tag=128bit |
| Entry Encrypt/Decrypt | AES-256-GCM | key=VaultKey(32B), iv=12B, tag=128bit |
| Encryption Version | 2 | from AuthResponse |

## Project Structure

```
web/
├── index.html
├── package.json
├── tsconfig.json
├── vite.config.ts
├── tailwind.config.ts
├── postcss.config.js
└── src/
    ├── main.tsx
    ├── App.tsx
    ├── index.css
    ├── api/
    │   ├── client.ts          # fetch wrapper with JWT + refresh interceptor
    │   ├── auth.ts            # login, register, refresh, logout, changePassword
    │   ├── vault.ts           # vault CRUD
    │   ├── twofa.ts           # 2FA endpoints
    │   └── devices.ts         # device management
    ├── crypto/
    │   ├── argon2.ts          # Argon2id Wasm wrapper
    │   ├── vaultKey.ts        # derive KEK, wrap/unwrap vault key
    │   ├── entries.ts         # AES-GCM encrypt/decrypt vault entries
    │   ├── generator.ts       # random password generator
    │   └── strength.ts        # password strength (0-10, min 4)
    ├── context/
    │   ├── AuthContext.tsx     # JWT tokens, user info, login/logout
    │   └── VaultContext.tsx    # in-memory vault key + entries cache
    ├── hooks/
    │   ├── useAutoLock.ts     # idle timer → wipe vault key
    │   └── useCopyToClipboard.ts
    ├── components/
    │   ├── Layout.tsx          # nav sidebar + header
    │   ├── ProtectedRoute.tsx
    │   ├── PasswordStrength.tsx
    │   ├── PasswordGenerator.tsx
    │   ├── SearchBar.tsx
    │   ├── CopyButton.tsx
    │   ├── EmptyState.tsx
    │   └── ErrorBoundary.tsx
    ├── pages/
    │   ├── LoginPage.tsx
    │   ├── RegisterPage.tsx
    │   ├── VaultPage.tsx          # list all entries
    │   ├── VaultEntryPage.tsx     # view single entry
    │   ├── VaultEntryForm.tsx     # add/edit entry
    │   ├── SettingsPage.tsx       # change password, 2FA, devices
    │   ├── AuditPage.tsx
    │   └── UnlockPage.tsx         # vault unlock after login
    └── lib/
        ├── utils.ts
        └── constants.ts
```

## Implementation Phases

### Phase 1 — Scaffold + Auth
- [ ] Vite + React + TS + Tailwind scaffold
- [ ] `api/client.ts` — fetch wrapper with JWT interceptor + 401 auto-refresh
- [ ] `api/auth.ts` — login, register, refresh, logout
- [ ] `context/AuthContext.tsx` — tokens, user state
- [ ] `components/ProtectedRoute.tsx` — redirect to login if unauthenticated
- [ ] `pages/LoginPage.tsx` — email + password form
- [ ] `pages/RegisterPage.tsx` — email + password + device setup form
- [ ] `App.tsx` — router setup

### Phase 2 — Crypto
- [ ] `crypto/argon2.ts` — `hash-wasm` argon2id wrapper
- [ ] `crypto/vaultKey.ts` — KEK derivation + vault key wrap/unwrap (AES-GCM)
- [ ] `crypto/entries.ts` — entry encrypt/decrypt (AES-GCM)
- [ ] `crypto/generator.ts` — secure password generator
- [ ] `crypto/strength.ts` — password strength (0-10 scale)
- [ ] `context/VaultContext.tsx` — in-memory vault key + entries cache
- [ ] `pages/UnlockPage.tsx` — derive KEK + unwrap vault key after login
- [ ] `hooks/useAutoLock.ts` — idle timer, wipe vault key

### Phase 3 — Vault CRUD
- [ ] `api/vault.ts` — vault CRUD API calls
- [ ] `pages/VaultPage.tsx` — list entries, search/filter, decrypt on display
- [ ] `pages/VaultEntryForm.tsx` — add entry (encrypt → POST)
- [ ] `pages/VaultEntryPage.tsx` — view/edit entry (decrypt → display → encrypt → PUT)
- [ ] `components/EmptyState.tsx` — empty vault state

### Phase 4 — Settings
- [ ] `api/twofa.ts` — 2FA API calls
- [ ] `api/devices.ts` — device API calls
- [ ] `pages/SettingsPage.tsx` — tabs: security, 2FA, devices, audit
- [ ] Change password flow — re-encrypt all entries client-side
- [ ] 2FA setup — display QR code, enable/disable
- [ ] Device management — list/remove
- [ ] Audit log viewer — paginated table

### Phase 5 — Polish
- [ ] `components/PasswordStrength.tsx` — visual strength bar
- [ ] `components/PasswordGenerator.tsx` — generator dialog
- [ ] `components/CopyButton.tsx` — copy with 30s auto-clear
- [ ] `components/SearchBar.tsx` — filter entries
- [ ] `components/ErrorBoundary.tsx` — catch and display errors
- [ ] Loading/spinner components
- [ ] Responsive layout (mobile-friendly sidebar)

### Phase 6 — Security + Deploy
- [ ] CSP headers via Vite plugin or backend response header
- [ ] Error boundaries at route level
- [ ] Production build config
- [ ] Dockerfile for `web/` + docker-compose update
- [ ] Verify end-to-end: register → login → unlock → CRUD → change password

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

- Vault key lives only in `useRef()` / `Map` — never localStorage, never DOM
- Auto-lock wipes vault key after N minutes of inactivity
- Session tokens (JWT) stored in localStorage only
- Clipboard auto-clears after 30s
- All encryption/decryption happens client-side — zero-knowledge preserved
- HTTPS required in production (Web Crypto API requires secure context)
