import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from 'react'
import {
  login as apiLogin,
  register as apiRegister,
  logout as apiLogout,
  verifyTwoFactor as apiVerifyTwoFactor,
  getAuthSalt as apiGetAuthSalt,
  type AuthResponse,
  type TwoFactorLoginResponse,
} from '../api/auth'
import { setTokens, clearTokens } from '../api/client'
import { derivePasswordHash, deriveKek, generateSalt, generateVaultKey } from '../crypto/argon2'
import { unwrapVaultKey, wrapVaultKey } from '../crypto/vaultKey'

let _autoUnlockVaultKey: CryptoKey | null = null

export function consumeAutoUnlockVaultKey(): CryptoKey | null {
  const key = _autoUnlockVaultKey
  _autoUnlockVaultKey = null
  return key
}

function getDeviceId(): string {
  let id = localStorage.getItem('deviceId')
  if (!id) {
    id = crypto.randomUUID()
    localStorage.setItem('deviceId', id)
  }
  return id
}

interface User {
  id: string
  email: string
}

interface AuthState {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  authData: AuthResponse | null
}

interface AuthContextType extends AuthState {
  login: (email: string, password: string) => Promise<TwoFactorLoginResponse>
  verifyTwoFactor: (email: string, challengeId: string, code: string) => Promise<void>
  register: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | null>(null)

function persistCryptoMaterial(data: { authSalt: string; encryptionSalt: string; wrappedVaultKey: string; encryptionVersion: number }) {
  localStorage.setItem('authSalt', data.authSalt)
  localStorage.setItem('encryptionSalt', data.encryptionSalt)
  localStorage.setItem('wrappedVaultKey', data.wrappedVaultKey)
  localStorage.setItem('encryptionVersion', String(data.encryptionVersion))
}

function clearCryptoMaterial() {
  localStorage.removeItem('authSalt')
  localStorage.removeItem('encryptionSalt')
  localStorage.removeItem('wrappedVaultKey')
  localStorage.removeItem('encryptionVersion')
}

function parseUserFromToken(token: string): User | null {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]))
    return { id: payload.sub || payload.userId, email: payload.email }
  } catch {
    return null
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    isAuthenticated: false,
    isLoading: true,
    authData: null,
  })

  useEffect(() => {
    silentRefresh()
  }, [])

  async function silentRefresh() {
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL || '/api/v1'}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      })
      if (!res.ok) {
        setState({ user: null, isAuthenticated: false, isLoading: false, authData: null })
        return
      }
      const json = await res.json()
      const token = json.data.accessToken
      if (!token) {
        setState({ user: null, isAuthenticated: false, isLoading: false, authData: null })
        return
      }
      setTokens(token)
      const user = parseUserFromToken(token)
      setState({
        user,
        isAuthenticated: true,
        isLoading: false,
        authData: null,
      })
    } catch {
      setState({ user: null, isAuthenticated: false, isLoading: false, authData: null })
    }
  }

  const login = useCallback(async (email: string, password: string): Promise<TwoFactorLoginResponse> => {
    let authSalt = localStorage.getItem('authSalt')
    if (!authSalt) {
      const saltRes = await apiGetAuthSalt(email)
      authSalt = saltRes.authSalt
    }
    const res = await apiLogin({
      email,
      authHash: await derivePasswordHash(password, authSalt),
      deviceName: 'Web Browser',
      deviceId: getDeviceId(),
    })
    if (!res.twoFactorRequired && res.accessToken) {
      try {
        const kek = await deriveKek(password, res.encryptionSalt!)
        const vaultKey = await unwrapVaultKey(kek, res.wrappedVaultKey!)
        _autoUnlockVaultKey = vaultKey
      } catch {
        // Vault unlock will require manual password entry
      }
      setTokens(res.accessToken)
      persistCryptoMaterial({
        authSalt: res.authSalt,
        encryptionSalt: res.encryptionSalt!,
        wrappedVaultKey: res.wrappedVaultKey!,
        encryptionVersion: res.encryptionVersion!,
      })
      setState({
        user: { id: res.userId, email: res.email },
        isAuthenticated: true,
        isLoading: false,
        authData: {
          accessToken: res.accessToken,
          userId: res.userId,
          email: res.email,
          authSalt: res.authSalt,
          encryptionSalt: res.encryptionSalt!,
          wrappedVaultKey: res.wrappedVaultKey!,
          encryptionVersion: res.encryptionVersion!,
        },
      })
    }
    return res
  }, [])

  const verifyTwoFactor = useCallback(async (email: string, challengeId: string, code: string) => {
    const res = await apiVerifyTwoFactor({ email, challengeId, code })
    setTokens(res.accessToken)
    persistCryptoMaterial({
      authSalt: res.authSalt,
      encryptionSalt: res.encryptionSalt,
      wrappedVaultKey: res.wrappedVaultKey,
      encryptionVersion: res.encryptionVersion,
    })
    setState({
      user: { id: res.userId, email: res.email },
      isAuthenticated: true,
      isLoading: false,
      authData: res,
    })
  }, [])

  const register = useCallback(async (email: string, password: string) => {
    const authSalt = generateSalt()
    const encryptionSalt = generateSalt()
    const vaultKey = await generateVaultKey()
    const authHash = await derivePasswordHash(password, authSalt)
    const kek = await deriveKek(password, encryptionSalt)
    const wrappedVaultKey = await wrapVaultKey(kek, vaultKey)
    _autoUnlockVaultKey = vaultKey

    const res = await apiRegister({
      email,
      authHash,
      authSalt,
      encryptionSalt,
      wrappedVaultKey,
      encryptionVersion: 2,
    })
    setTokens(res.accessToken)
    persistCryptoMaterial({
      authSalt,
      encryptionSalt: res.encryptionSalt,
      wrappedVaultKey: res.wrappedVaultKey,
      encryptionVersion: res.encryptionVersion,
    })
    setState({
      user: { id: res.userId, email: res.email },
      isAuthenticated: true,
      isLoading: false,
      authData: res,
    })
  }, [])

  const logout = useCallback(async () => {
    try {
      await apiLogout()
    } catch {
      // ignore
    }
    clearTokens()
    clearCryptoMaterial()
    _autoUnlockVaultKey = null
    setState({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      authData: null,
    })
  }, [])

  return (
    <AuthContext.Provider
      value={{ ...state, login, verifyTwoFactor, register, logout }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
