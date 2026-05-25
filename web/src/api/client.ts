const API_BASE = import.meta.env.VITE_API_URL || '/api/v1'

interface ApiResponse<T> {
  success: boolean
  message: string
  data: T
}

interface TokenStore {
  accessToken: string | null
}

let store: TokenStore = { accessToken: null }

export function getAccessToken() {
  return store.accessToken
}

export function setTokens(access: string) {
  store = { accessToken: access }
}

export function clearTokens() {
  store = { accessToken: null }
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
      const json: ApiResponse<{ accessToken: string }> = await res.json()
      setTokens(json.data.accessToken)
      return json.data.accessToken
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

  let res = await fetch(`${API_BASE}${path}`, { ...options, headers, credentials: 'include' })

  if (res.status === 401) {
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

  const json: ApiResponse<T> = await res.json()
  return json.data
}
