import {
  createContext,
  useContext,
  useState,
  useCallback,
  useRef,
  useEffect,
  type ReactNode,
} from 'react'
import { deriveKek } from '../crypto/argon2'
import { unwrapVaultKey, wrapVaultKey } from '../crypto/vaultKey'
import { encryptEntry, decryptEntry } from '../crypto/entries'
import { bytesToBase64, generateRandomBytes } from '../crypto/util'
import {
  getVaultEntries,
  createVaultEntry,
  updateVaultEntry,
  deleteVaultEntry,
  type VaultEntryResponse,
} from '../api/vault'
import { changePassword } from '../api/auth'
import { setTokens } from '../api/client'
import { useAuth } from './AuthContext'

export interface EntryFields {
  name: string
  username: string
  password: string
  url: string
  notes: string
}

interface VaultContextType {
  isUnlocked: boolean
  isLoading: boolean
  error: string | null
  unlock: (password: string) => Promise<void>
  lock: () => void
  clearError: () => void

  entries: VaultEntryResponse[]
  decrypted: Record<string, EntryFields>
  isLoadingEntries: boolean
  entryError: string | null
  loadEntries: () => Promise<void>
  createEntry: (data: EntryFields) => Promise<void>
  updateEntry: (id: string, data: EntryFields) => Promise<void>
  deleteEntry: (id: string) => Promise<void>
  clearEntryError: () => void
  changeMasterPassword: (currentPassword: string, newPassword: string) => Promise<void>
}

const VaultContext = createContext<VaultContextType | null>(null)

export function VaultProvider({ children }: { children: ReactNode }) {
  const { authData } = useAuth()
  const vaultKeyRef = useRef<CryptoKey | null>(null)
  const [isUnlocked, setIsUnlocked] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [entries, setEntries] = useState<VaultEntryResponse[]>([])
  const [decrypted, setDecrypted] = useState<Record<string, EntryFields>>({})
  const [isLoadingEntries, setIsLoadingEntries] = useState(false)
  const [entryError, setEntryError] = useState<string | null>(null)

  const lock = useCallback(() => {
    vaultKeyRef.current = null
    setIsUnlocked(false)
    setError(null)
    setEntries([])
    setDecrypted({})
  }, [])

  const unlock = useCallback(async (password: string) => {
    const salt = localStorage.getItem('encryptionSalt')
    const wrapped = localStorage.getItem('wrappedVaultKey')
    if (!salt || !wrapped) {
      setError('No vault key material found. Please log in again.')
      return
    }

    setIsLoading(true)
    setError(null)
    try {
      const kek = await deriveKek(password, salt)
      const vaultKey = await unwrapVaultKey(kek, wrapped)
      vaultKeyRef.current = vaultKey
      setIsUnlocked(true)
    } catch {
      vaultKeyRef.current = null
      setError('Failed to unlock vault. Check your master password.')
    } finally {
      setIsLoading(false)
    }
  }, [])

  const clearError = useCallback(() => setError(null), [])
  const clearEntryError = useCallback(() => setEntryError(null), [])

  const loadEntries = useCallback(async () => {
    const key = vaultKeyRef.current
    if (!key) return

    setIsLoadingEntries(true)
    setEntryError(null)
    try {
      const res = await getVaultEntries()
      setEntries(res.entries)

      const cache: Record<string, EntryFields> = {}
      await Promise.all(
        res.entries.map(async (entry) => {
          try {
            const plain = await decryptEntry(
              key,
              entry.encryptedData,
              entry.iv,
            )
            cache[entry.id] = JSON.parse(plain)
          } catch {
            cache[entry.id] = {
              name: 'Decryption failed',
              username: '',
              password: '',
              url: '',
              notes: '',
            }
          }
        }),
      )
      setDecrypted(cache)
    } catch (e) {
      setEntryError(
        e instanceof Error ? e.message : 'Failed to load entries',
      )
    } finally {
      setIsLoadingEntries(false)
    }
  }, [])

  const createEntry = useCallback(
    async (data: EntryFields) => {
      const key = vaultKeyRef.current
      if (!key) return

      setEntryError(null)
      try {
        const encrypted = await encryptEntry(key, JSON.stringify(data))
        const created = await createVaultEntry({
          encryptedData: encrypted.encryptedData,
          iv: encrypted.iv,
        })
        setEntries((prev) => [...prev, created])
        setDecrypted((prev) => ({ ...prev, [created.id]: data }))
      } catch (e) {
        setEntryError(
          e instanceof Error ? e.message : 'Failed to create entry',
        )
        throw e
      }
    },
    [],
  )

  const updateEntry = useCallback(
    async (id: string, data: EntryFields) => {
      const key = vaultKeyRef.current
      if (!key) return

      setEntryError(null)
      try {
        const encrypted = await encryptEntry(key, JSON.stringify(data))
        const updated = await updateVaultEntry(id, {
          encryptedData: encrypted.encryptedData,
          iv: encrypted.iv,
        })
        setEntries((prev) =>
          prev.map((e) => (e.id === id ? updated : e)),
        )
        setDecrypted((prev) => ({ ...prev, [id]: data }))
      } catch (e) {
        setEntryError(
          e instanceof Error ? e.message : 'Failed to update entry',
        )
        throw e
      }
    },
    [],
  )

  const deleteEntry = useCallback(async (id: string) => {
    setEntryError(null)
    try {
      await deleteVaultEntry(id)
      setEntries((prev) => prev.filter((e) => e.id !== id))
      setDecrypted((prev) => {
        const next = { ...prev }
        delete next[id]
        return next
      })
    } catch (e) {
      setEntryError(
        e instanceof Error ? e.message : 'Failed to delete entry',
      )
      throw e
    }
  }, [])

  const changeMasterPassword = useCallback(
    async (currentPassword: string, newPassword: string) => {
      const currentSalt = localStorage.getItem('encryptionSalt')
      const wrapped = localStorage.getItem('wrappedVaultKey')
      if (!currentSalt || !wrapped) throw new Error('No vault key material')

      let vaultKey = vaultKeyRef.current
      if (!vaultKey) {
        const kek = await deriveKek(currentPassword, currentSalt)
        vaultKey = await unwrapVaultKey(kek, wrapped)
      }

      const newSalt = bytesToBase64(generateRandomBytes(16))
      const newKek = await deriveKek(newPassword, newSalt)
      const newWrapped = await wrapVaultKey(newKek, vaultKey)

      const res = await changePassword({
        currentPassword,
        newPassword,
        wrappedVaultKey: newWrapped,
        newEncryptionSalt: newSalt,
        entries: [],
      })

      localStorage.setItem('encryptionSalt', res.encryptionSalt)
      localStorage.setItem('wrappedVaultKey', res.wrappedVaultKey)
      localStorage.setItem('encryptionVersion', String(res.encryptionVersion))
      setTokens(res.accessToken, res.refreshToken)
    },
    [],
  )

  useEffect(() => {
    if (authData) {
      setEntries([])
      setDecrypted({})
      const pw = consumeMasterPassword()
      if (pw) {
        ;(async () => {
          try {
            const salt = localStorage.getItem('encryptionSalt')
            const wrapped = localStorage.getItem('wrappedVaultKey')
            if (salt && wrapped) {
              const kek = await deriveKek(pw, salt)
              const vaultKey = await unwrapVaultKey(kek, wrapped)
              vaultKeyRef.current = vaultKey
              setIsUnlocked(true)
            }
          } catch {
            // auto-unlock failed, user will need to unlock manually
          }
        })()
      }
    }
  }, [authData, consumeMasterPassword])

  return (
    <VaultContext.Provider
      value={{
        isUnlocked,
        isLoading,
        error,
        unlock,
        lock,
        clearError,

        entries,
        decrypted,
        isLoadingEntries,
        entryError,
        loadEntries,
        createEntry,
        updateEntry,
        deleteEntry,
        clearEntryError,
        changeMasterPassword,
      }}
    >
      {children}
    </VaultContext.Provider>
  )
}

export function useVault() {
  const ctx = useContext(VaultContext)
  if (!ctx) throw new Error('useVault must be used within VaultProvider')
  return ctx
}
