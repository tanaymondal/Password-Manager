import { getTokens, setTokens, clearTokens } from './storage'

const API_BASE = 'https://vault.tanay.pro/api/v1'

interface ApiResponse<T> {
  success: boolean
  message: string
  data: T
}

let refreshPromise: Promise<string | null> | null = null

async function refreshAccessToken(): Promise<string | null> {
  const tokens = await getTokens()
  if (!tokens?.refreshToken) return null

  if (refreshPromise) return refreshPromise

  refreshPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: tokens.refreshToken }),
      })
      if (!res.ok) {
        await clearTokens()
        return null
      }
      const json: ApiResponse<{ accessToken: string; refreshToken: string }> = await res.json()
      await setTokens({ accessToken: json.data.accessToken, refreshToken: json.data.refreshToken })
      return json.data.accessToken
    } catch {
      await clearTokens()
      return null
    } finally {
      refreshPromise = null
    }
  })()

  return refreshPromise
}

export async function apiClient<T>(path: string, options: RequestInit = {}): Promise<T> {
  const tokens = await getTokens()
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }

  if (tokens?.accessToken) {
    headers['Authorization'] = `Bearer ${tokens.accessToken}`
  }

  let res = await fetch(`${API_BASE}${path}`, { ...options, headers })

  if (res.status === 401 && tokens?.refreshToken) {
    const newToken = await refreshAccessToken()
    if (newToken) {
      headers['Authorization'] = `Bearer ${newToken}`
      res = await fetch(`${API_BASE}${path}`, { ...options, headers })
    } else {
      throw new Error('Session expired. Please login again.')
    }
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ message: res.statusText }))
    throw new Error(body.message || `Request failed (${res.status})`)
  }

  if (res.status === 204) return undefined as T

  const json: ApiResponse<T> = await res.json()
  return json.data
}

export async function apiPrelogin(email: string) {
  return apiClient<{ authSalt: string }>('/auth/prelogin', {
    method: 'POST',
    body: JSON.stringify({ email }),
  })
}

export async function apiLogin(data: {
  email: string
  authHash: string
  deviceName: string
  deviceId: string
}) {
  return apiClient<{
    twoFactorRequired: boolean
    userId: string
    email: string
    challengeId?: string
    authSalt: string
    encryptionSalt: string
    wrappedVaultKey: string
    encryptionVersion: number
    accessToken: string | null
    refreshToken: string | null
  }>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export async function apiGetVaultEntries() {
  return apiClient<{ entries: { id: string; encryptedData: string; iv: string; version: number; createdAt: string; updatedAt: string }[]; count: number }>('/vault')
}

export async function verifyTwoFactor(email: string, challengeId: string, code: string) {
  return apiClient<{
    accessToken: string
    refreshToken: string
    userId: string
    email: string
    authSalt: string
    encryptionSalt: string
    wrappedVaultKey: string
    encryptionVersion: number
  }>('/auth/verify-2fa', {
    method: 'POST',
    body: JSON.stringify({ email, challengeId, code }),
  })
}

export async function apiLogout() {
  const tokens = await getTokens()
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (tokens?.accessToken) headers['Authorization'] = `Bearer ${tokens.accessToken}`
  await fetch(`${API_BASE}/auth/logout`, {
    method: 'POST',
    headers,
    body: tokens?.refreshToken ? JSON.stringify({ refreshToken: tokens.refreshToken }) : undefined,
  }).catch(() => {})
}
