const API_BASE = import.meta.env.VITE_API_URL || '/api/v1'

import { setCryptoMaterial } from '../store/cryptoMaterial'

interface ApiResponse<T> {
  success: boolean
  message: string
  data: T
}

interface TokenStore {
  accessToken: string | null
}

let store: TokenStore = { accessToken: null }
let lastSecurityVersion: string | null = null
let onPasswordChanged: (() => void) | null = null

export function setOnPasswordChanged(callback: () => void) {
  onPasswordChanged = callback
}

export function getAccessToken() {
  return store.accessToken
}

export function setTokens(access: string) {
  store = { accessToken: access }
  lastSecurityVersion = null // reset so stale value doesn't trigger false mismatch after login
}

export function clearTokens() {
  store = { accessToken: null }
  lastSecurityVersion = null
}

export function loadTokens(): TokenStore {
  return store
}

let refreshPromise: Promise<string | null> | null = null

async function refreshAccessToken(): Promise<string | null> {
  if (refreshPromise) return refreshPromise

  refreshPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      })
      if (!res.ok) {
        clearTokens()
        return null
      }
      const json: ApiResponse<Record<string, unknown>> = await res.json()
      const data = json.data
      setTokens(data.accessToken as string)
      if (data.encryptionSalt && data.wrappedVaultKey) {
        setCryptoMaterial({
          authSalt: data.authSalt as string,
          encryptionSalt: data.encryptionSalt as string,
          wrappedVaultKey: data.wrappedVaultKey as string,
          encryptionVersion: (data.encryptionVersion as number) ?? 2,
        })
      }
      return data.accessToken as string
    } catch {
      clearTokens()
      return null
    } finally {
      refreshPromise = null
    }
  })()

  return refreshPromise
}

export async function apiClient<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }

  if (store.accessToken) {
    headers['Authorization'] = `Bearer ${store.accessToken}`
  }

  if (options.headers) {
    const customHeaders = options.headers as Record<string, string>
    for (const key of Object.keys(customHeaders)) {
      headers[key] = customHeaders[key]
    }
  }

  let res = await fetch(`${API_BASE}${path}`, { ...options, headers, credentials: 'include' })

  const isPublicEndpoint = ['/auth/login', '/auth/register', '/auth/auth-salt'].some(p =>
    path.startsWith(p),
  )

  if (res.status === 401 && !isPublicEndpoint) {
    const newToken = await refreshAccessToken()
    if (newToken) {
      headers['Authorization'] = `Bearer ${newToken}`
      res = await fetch(`${API_BASE}${path}`, { ...options, headers, credentials: 'include' })
    } else {
      throw new Error('Session expired. Please login again.')
    }
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({
      message: res.statusText,
    }))
    throw new Error(body.message || `Request failed (${res.status})`)
  }

  if (res.status === 204) return undefined as T

  // Check for password-changed-on-another-device via security version header
  const securityVersion = res.headers.get('X-Security-Version')
  if (securityVersion) {
    if (lastSecurityVersion && lastSecurityVersion !== securityVersion) {
      onPasswordChanged?.()
      throw new Error('Password changed on another device. Please log in again.')
    }
    lastSecurityVersion = securityVersion
  }

  const json: ApiResponse<T> = await res.json()
  return json.data
}
