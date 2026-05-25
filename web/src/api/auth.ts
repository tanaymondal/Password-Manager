import { apiClient } from './client'

export interface AuthResponse {
  accessToken: string
  userId: string
  email: string
  authSalt: string
  encryptionSalt: string
  wrappedVaultKey: string
  encryptionVersion: number
}

export interface TwoFactorLoginResponse {
  twoFactorRequired: boolean
  userId: string
  email: string
  challengeId: string
  authSalt: string
  encryptionSalt: string | null
  wrappedVaultKey: string | null
  encryptionVersion: number | null
  accessToken: string | null
}

export interface LoginRequest {
  email: string
  authHash: string
  deviceName: string
  deviceId: string
}

export interface RegisterRequest {
  email: string
  authHash: string
  authSalt: string
  encryptionSalt: string
  wrappedVaultKey: string
  encryptionVersion: number
  deviceId?: string
}

export function login(data: LoginRequest) {
  return apiClient<TwoFactorLoginResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export interface TwoFactorVerifyRequest {
  email: string
  challengeId: string
  code: string
}

export function verifyTwoFactor(data: TwoFactorVerifyRequest) {
  return apiClient<AuthResponse>('/auth/verify-2fa', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export function register(data: RegisterRequest) {
  return apiClient<AuthResponse>('/auth/register', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export async function checkBreach(password: string): Promise<boolean> {
  const sha1 = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password))
  const hash = Array.from(new Uint8Array(sha1)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
  const prefix = hash.slice(0, 5)
  const suffix = hash.slice(5)
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`)
  if (!res.ok) return false
  const body = await res.text()
  return body.split('\n').some(line => line.startsWith(suffix))
}

export function getAuthSalt(email: string) {
  return apiClient<{ authSalt: string }>('/auth/auth-salt', {
    method: 'POST',
    body: JSON.stringify({ email }),
  })
}

export async function logout() {
  try {
    await fetch(`${import.meta.env.VITE_API_URL || '/api/v1'}/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
    })
  } catch {
    // ignore
  }
}

export interface ChangePasswordRequest {
  current_auth_hash: string
  new_auth_hash: string
  new_auth_salt: string
  wrapped_vault_key: string
  new_encryption_salt: string
  entries: { id?: string; encryptedData: string; iv: string }[]
}

export interface ChangePasswordResponse {
  accessToken: string
  encryptionSalt: string
  wrappedVaultKey: string
  encryptionVersion: number
  userId: string
  email: string
}

export function changePassword(data: ChangePasswordRequest) {
  return apiClient<ChangePasswordResponse>('/auth/change-password', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}
