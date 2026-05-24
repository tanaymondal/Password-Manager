import { apiClient } from './client'

export interface AuthResponse {
  accessToken: string
  refreshToken: string
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
  encryptionSalt: string
  wrappedVaultKey: string
  encryptionVersion: number
  accessToken: string | null
  refreshToken: string | null
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

export function getAuthSalt(email: string) {
  return apiClient<{ authSalt: string }>('/auth/auth-salt', {
    method: 'POST',
    body: JSON.stringify({ email }),
  })
}

export async function logout() {
  const refreshToken = localStorage.getItem('refreshToken')
  const accessToken = localStorage.getItem('accessToken')
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`
  await fetch(`${import.meta.env.VITE_API_URL || '/api/v1'}/auth/logout`, {
    method: 'POST',
    headers,
    body: refreshToken ? JSON.stringify({ refreshToken }) : undefined,
  }).catch(() => {})
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
  refreshToken: string
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
