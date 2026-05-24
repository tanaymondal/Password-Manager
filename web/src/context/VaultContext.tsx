import {
  createContext,
  useContext,
  useState,
  useCallback,
  useRef,
  useEffect,
  type ReactNode,
} from 'react'
import { deriveKek, derivePasswordHash, generateSalt, generateVaultKey } from '../crypto/argon2'
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
  crossTabLocked: boolean
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
  changeMasterPassword: (currentPassword: string, newPassword: string, onProgress?: (pct: number) => void) => Promise<void>
}

const VaultContext = createContext<VaultContextType | null>(null)

export function VaultProvider({ children }: { children: ReactNode }) {
  const vaultKeyRef = useRef<CryptoKey | null>(null)
  const [isUnlocked, setIsUnlocked] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [crossTabLocked, setCrossTabLocked] = useState(false)

  const [entries, setEntries] = useState<VaultEntryResponse[]>([])
  const [decrypted, setDecrypted] = useState<Record<string, EntryFields>>({})
  const [isLoadingEntries, setIsLoadingEntries] = useState(false)
  const [entryError, setEntryError] = useState<string | null>(null)

  useEffect(() => {
    const handleStorage = (e: StorageEvent) => {
      if (e.key === 'encryptionSalt' || e.key === 'wrappedVaultKey') {
        vaultKeyRef.current = null
        setIsUnlocked(false)
        setCrossTabLocked(true)
        setEntries([])
        setDecrypted({})
        setError('Your master password was changed in another session. Please log out and log back in.')
      }
    }
    window.addEventListener('storage', handleStorage)
    return () => window.removeEventListener('storage', handleStorage)
  }, [])

  const lock = useCallback(() => {
    vaultKeyRef.current = null
    setIsUnlocked(false)
    setCrossTabLocked(false)
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
    async (currentPassword: string, newPassword: string, onProgress?: (pct: number) => void) => {
      const currentSalt = localStorage.getItem('encryptionSalt')
      const wrapped = localStorage.getItem('wrappedVaultKey')
      if (!currentSalt || !wrapped) throw new Error('No vault key material')

      onProgress?.(0.1)
      let oldVaultKey = vaultKeyRef.current
      if (!oldVaultKey) {
        const kek = await deriveKek(currentPassword, currentSalt)
        oldVaultKey = await unwrapVaultKey(kek, wrapped)
      }

      onProgress?.(0.25)
      const entriesRes = await getVaultEntries()
      const existingEntries = entriesRes.entries

      onProgress?.(0.4)
      const newVaultKey = await generateVaultKey()

      onProgress?.(0.55)
      const reEncryptedEntries = await Promise.all(
        existingEntries.map(async (entry) => {
          const plaintext = await decryptEntry(oldVaultKey, entry.encryptedData, entry.iv)
          const encrypted = await encryptEntry(newVaultKey, plaintext)
          return { id: entry.id, ...encrypted }
        }),
      )

      onProgress?.(0.75)
      const newSalt = bytesToBase64(generateRandomBytes(16))
      const newKek = await deriveKek(newPassword, newSalt)
      const newWrapped = await wrapVaultKey(newKek, newVaultKey)

      onProgress?.(0.85)
      const currentAuthSalt = localStorage.getItem('authSalt')
      if (!currentAuthSalt) throw new Error('No auth salt found. Please log in again.')
      const newAuthSalt = generateSalt()
      const currentAuthHash = await derivePasswordHash(currentPassword, currentAuthSalt)
      const newAuthHash = await derivePasswordHash(newPassword, newAuthSalt)

      onProgress?.(0.95)
      const res = await changePassword({
        current_auth_hash: currentAuthHash,
        new_auth_hash: newAuthHash,
        new_auth_salt: newAuthSalt,
        wrapped_vault_key: newWrapped,
        new_encryption_salt: newSalt,
        entries: reEncryptedEntries,
      })

      vaultKeyRef.current = newVaultKey

      localStorage.setItem('encryptionSalt', res.encryptionSalt)
      localStorage.setItem('wrappedVaultKey', res.wrappedVaultKey)
      localStorage.setItem('encryptionVersion', String(res.encryptionVersion))
      setTokens(res.accessToken, res.refreshToken)
    },
    [],
  )

  return (
    <VaultContext.Provider
      value={{
        isUnlocked,
        isLoading,
        error,
        crossTabLocked,
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
