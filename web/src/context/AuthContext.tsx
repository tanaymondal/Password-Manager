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
  prelogin as apiPrelogin,
  register as apiRegister,
  logout as apiLogout,
  verifyTwoFactor as apiVerifyTwoFactor,
  checkBreach,
  type AuthResponse,
  type TwoFactorLoginResponse,
} from '../api/auth'
import { setTokens, clearTokens } from '../api/client'
import { derivePasswordHash, deriveKek, generateSalt, generateVaultKey } from '../crypto/argon2'
import { unwrapVaultKey, wrapVaultKey } from '../crypto/vaultKey'
import {
  setCryptoMaterial,
  setAutoUnlockVaultKey,
  consumeAutoUnlockVaultKey,
  clearAll,
  getCryptoMaterial,
} from '../store/cryptoMaterial'

export { consumeAutoUnlockVaultKey, getCryptoMaterial }

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
      const data = json.data
      if (!data.accessToken) {
        setState({ user: null, isAuthenticated: false, isLoading: false, authData: null })
        return
      }
      setTokens(data.accessToken)
      if (data.encryptionSalt && data.wrappedVaultKey) {
        setCryptoMaterial({
          authSalt: data.authSalt,
          encryptionSalt: data.encryptionSalt,
          wrappedVaultKey: data.wrappedVaultKey,
          encryptionVersion: data.encryptionVersion,
        })
      }
      const user = parseUserFromToken(data.accessToken)
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
    const pre = await apiPrelogin(email)
    const res = await apiLogin({
      email,
      authHash: await derivePasswordHash(password, pre.authSalt),
      deviceName: 'Web Browser',
      deviceId: getDeviceId(),
    })

    if (res.twoFactorMethods && !res.twoFactorMethods.includes('totp')) {
      const authRes = await apiVerifyTwoFactor({ email, challengeId: res.challengeId, code: '' })
      try {
        const kek = await deriveKek(password, authRes.encryptionSalt)
        const vaultKey = await unwrapVaultKey(kek, authRes.wrappedVaultKey)
        setAutoUnlockVaultKey(vaultKey)
      } catch {
      }
      setTokens(authRes.accessToken)
      setCryptoMaterial({
        authSalt: authRes.authSalt,
        encryptionSalt: authRes.encryptionSalt,
        wrappedVaultKey: authRes.wrappedVaultKey,
        encryptionVersion: authRes.encryptionVersion,
      })
      setState({
        user: { id: authRes.userId, email: authRes.email },
        isAuthenticated: true,
        isLoading: false,
        authData: authRes,
      })
    }

    return res
  }, [])

  const verifyTwoFactor = useCallback(async (email: string, challengeId: string, code: string) => {
    const res = await apiVerifyTwoFactor({ email, challengeId, code })
    setTokens(res.accessToken)
    setCryptoMaterial({
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
    if (await checkBreach(password)) {
      throw new Error('This password has been exposed in a data breach. Please choose a different password.')
    }
    const authSalt = generateSalt()
    const encryptionSalt = generateSalt()
    const vaultKey = await generateVaultKey()
    const authHash = await derivePasswordHash(password, authSalt)
    const kek = await deriveKek(password, encryptionSalt)
    const wrappedVaultKey = await wrapVaultKey(kek, vaultKey)
    setAutoUnlockVaultKey(vaultKey)

    const res = await apiRegister({
      email,
      authHash,
      authSalt,
      encryptionSalt,
      wrappedVaultKey,
      encryptionVersion: 2,
      deviceId: getDeviceId(),
    })
    setTokens(res.accessToken)
    setCryptoMaterial({
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

  const logout = useCallback(async () => {
    try {
      await apiLogout()
    } catch {
    }
    clearTokens()
    clearAll()
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
