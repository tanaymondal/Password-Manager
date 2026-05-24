const API_BASE = import.meta.env.VITE_API_URL || '/api/v1'

interface ApiResponse<T> {
  success: boolean
  message: string
  data: T
}

interface TokenStore {
  accessToken: string | null
  refreshToken: string | null
}

let store: TokenStore = { accessToken: null, refreshToken: null }

export function getAccessToken() {
  return store.accessToken
}

export function setTokens(access: string, refresh: string) {
  store = { accessToken: access, refreshToken: refresh }
  localStorage.setItem('accessToken', access)
  localStorage.setItem('refreshToken', refresh)
}

export function clearTokens() {
  store = { accessToken: null, refreshToken: null }
  localStorage.removeItem('accessToken')
  localStorage.removeItem('refreshToken')
}

export function loadTokens(): TokenStore {
  const access = localStorage.getItem('accessToken')
  const refresh = localStorage.getItem('refreshToken')
  store = { accessToken: access, refreshToken: refresh }
  return store
}

let refreshPromise: Promise<string | null> | null = null

async function refreshAccessToken(): Promise<string | null> {
  if (!store.refreshToken) return null

  if (refreshPromise) return refreshPromise

  refreshPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: store.refreshToken }),
      })
      if (!res.ok) {
        clearTokens()
        return null
      }
      const json: ApiResponse<{
        accessToken: string
        refreshToken: string
      }> = await res.json()
      setTokens(json.data.accessToken, json.data.refreshToken)
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

  let res = await fetch(`${API_BASE}${path}`, { ...options, headers })

  if (res.status === 401 && store.refreshToken) {
    const newToken = await refreshAccessToken()
    if (newToken) {
      headers['Authorization'] = `Bearer ${newToken}`
      res = await fetch(`${API_BASE}${path}`, { ...options, headers })
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
