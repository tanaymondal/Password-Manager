import { apiClient } from './client'

export interface AuthResponse {
  accessToken: string
  refreshToken: string
  userId: string
  email: string
  encryptionSalt: string
  wrappedVaultKey: string
  encryptionVersion: number
}

export interface TwoFactorLoginResponse {
  twoFactorRequired: boolean
  userId: string
  email: string
  encryptionSalt: string
  wrappedVaultKey: string
  encryptionVersion: number
  accessToken: string | null
  refreshToken: string | null
}

export interface LoginRequest {
  email: string
  password: string
  deviceName: string
  deviceId: string
}

export interface RegisterRequest {
  email: string
  password: string
  deviceName: string
  deviceId: string
}

export function login(data: LoginRequest) {
  return apiClient<TwoFactorLoginResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export interface TwoFactorVerifyRequest {
  email: string
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

export function logout() {
  return apiClient<void>('/auth/logout', { method: 'POST' })
}

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
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
