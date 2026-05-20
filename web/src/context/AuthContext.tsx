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
  type AuthResponse,
  type TwoFactorLoginResponse,
} from '../api/auth'
import { setTokens, clearTokens, loadTokens } from '../api/client'

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
  verifyTwoFactor: (email: string, code: string) => Promise<void>
  register: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | null>(null)

function persistCryptoMaterial(data: { encryptionSalt: string; wrappedVaultKey: string; encryptionVersion: number }) {
  localStorage.setItem('encryptionSalt', data.encryptionSalt)
  localStorage.setItem('wrappedVaultKey', data.wrappedVaultKey)
  localStorage.setItem('encryptionVersion', String(data.encryptionVersion))
}

function clearCryptoMaterial() {
  localStorage.removeItem('encryptionSalt')
  localStorage.removeItem('wrappedVaultKey')
  localStorage.removeItem('encryptionVersion')
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(() => {
    const tokens = loadTokens()
    if (tokens.accessToken) {
      return {
        user: null,
        isAuthenticated: true,
        isLoading: true,
        authData: null,
      }
    }
    return {
      user: null,
      isAuthenticated: false,
      isLoading: false,
      authData: null,
    }
  })

  useEffect(() => {
    const tokens = loadTokens()
    if (tokens.accessToken) {
      try {
        const payload = JSON.parse(atob(tokens.accessToken.split('.')[1]))
        setState({
          user: { id: payload.sub || payload.userId, email: payload.email },
          isAuthenticated: true,
          isLoading: false,
          authData: null,
        })
      } catch {
        clearTokens()
        clearCryptoMaterial()
        setState({
          user: null,
          isAuthenticated: false,
          isLoading: false,
          authData: null,
        })
      }
    }
  }, [])

  const login = useCallback(async (email: string, password: string): Promise<TwoFactorLoginResponse> => {
    const res = await apiLogin({
      email,
      password,
      deviceName: 'Web Browser',
      deviceId: getDeviceId(),
    })
    if (!res.twoFactorRequired && res.accessToken && res.refreshToken) {
      setTokens(res.accessToken, res.refreshToken)
      persistCryptoMaterial({
        encryptionSalt: res.encryptionSalt!,
        wrappedVaultKey: res.wrappedVaultKey!,
        encryptionVersion: res.encryptionVersion,
      })
      setState({
        user: { id: res.userId, email: res.email },
        isAuthenticated: true,
        isLoading: false,
        authData: {
          accessToken: res.accessToken,
          refreshToken: res.refreshToken,
          userId: res.userId,
          email: res.email,
          encryptionSalt: res.encryptionSalt,
          wrappedVaultKey: res.wrappedVaultKey,
          encryptionVersion: res.encryptionVersion,
        },
      })
    }
    return res
  }, [])

  const verifyTwoFactor = useCallback(async (email: string, code: string) => {
    const res = await apiVerifyTwoFactor({ email, code })
    setTokens(res.accessToken, res.refreshToken)
    persistCryptoMaterial(res)
    setState({
      user: { id: res.userId, email: res.email },
      isAuthenticated: true,
      isLoading: false,
      authData: res,
    })
  }, [])

  const register = useCallback(async (email: string, password: string) => {
    const res = await apiRegister({
      email,
      password,
      deviceName: 'Web Browser',
      deviceId: getDeviceId(),
    })
    setTokens(res.accessToken, res.refreshToken)
    persistCryptoMaterial(res)
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
