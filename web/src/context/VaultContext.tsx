import {
  createContext,
  useContext,
  useState,
  useCallback,
  useRef,
  useEffect,
  type ReactNode,
} from 'react'
import {
  deriveKek,
  derivePasswordHash,
} from '../crypto/argon2'
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
import { changePassword, checkBreach, upgradeKdf, requestSudo } from '../api/auth'
import { setTokens, setOnPasswordChanged } from '../api/client'
import { getCryptoMaterial, setCryptoMaterial } from '../store/cryptoMaterial'
import { getKdfConfig } from '../crypto/kdfConfig'

const CROSS_TAB_CHANNEL = 'securevault-crypto'

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
  unlock: (password: string, vaultKey?: CryptoKey) => Promise<void>
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
    const channel = new BroadcastChannel(CROSS_TAB_CHANNEL)
    channel.onmessage = (e) => {
      if (e.data === 'crypto-changed') {
        vaultKeyRef.current = null
        setIsUnlocked(false)
        setCrossTabLocked(true)
        setEntries([])
        setDecrypted({})
        setError('Your master password was changed in another session. Please log out and log back in.')
      }
    }

    setOnPasswordChanged(() => {
      vaultKeyRef.current = null
      setIsUnlocked(false)
      setCrossTabLocked(true)
      setEntries([])
      setDecrypted({})
      setError('Password changed on another device. Please log out and log back in.')
    })

    return () => {
      channel.close()
      setOnPasswordChanged(() => {})
    }
  }, [])

  const lock = useCallback(() => {
    vaultKeyRef.current = null
    setIsUnlocked(false)
    setCrossTabLocked(false)
    setError(null)
    setEntries([])
    setDecrypted({})
  }, [])

  const unlock = useCallback(async (password: string, vaultKey?: CryptoKey) => {
    if (vaultKey) {
      vaultKeyRef.current = vaultKey
      setIsUnlocked(true)
      return
    }

    const material = getCryptoMaterial()
    if (!material) {
      setError('No vault key material found. Please log in again.')
      return
    }

    setIsLoading(true)
    setError(null)
    try {
      const kek = await deriveKek(
        password,
        material.encryptionSalt,
        material.kdfIterations,
        material.kdfMemory,
        material.kdfParallelism
      )
      const vaultKeyDerived = await unwrapVaultKey(kek, material.wrappedVaultKey)
      vaultKeyRef.current = vaultKeyDerived
      setIsUnlocked(true)

      // Background KDF parameter upgrade check
      const cfg = await getKdfConfig()
      const currentMemory = material.kdfMemory || cfg.kdfMemory
      if (currentMemory < cfg.kdfMemory) {
        console.log('Background KDF parameter upgrade starting...')
        ;(async () => {
          try {
            const newAuthHash = await derivePasswordHash(
              password,
              material.authSalt,
              cfg.kdfIterations,
              cfg.kdfMemory,
              cfg.kdfParallelism
            )
            const newKek = await deriveKek(
              password,
              material.encryptionSalt,
              cfg.kdfIterations,
              cfg.kdfMemory,
              cfg.kdfParallelism
            )
            const newWrapped = await wrapVaultKey(newKek, vaultKeyDerived)

            // Obtain a sudo token by re-deriving the current auth hash with the
            // existing (pre-upgrade) KDF params so the server can verify it.
            const currentAuthHash = await derivePasswordHash(
              password,
              material.authSalt,
              material.kdfIterations,
              material.kdfMemory,
              material.kdfParallelism
            )
            const sudo = await requestSudo(currentAuthHash)

            await upgradeKdf({
              authHash: newAuthHash,
              wrappedVaultKey: newWrapped,
              kdfIterations: cfg.kdfIterations,
              kdfMemory: cfg.kdfMemory,
              kdfParallelism: cfg.kdfParallelism,
            }, sudo.sudoToken)

            // Update local material in store
            setCryptoMaterial({
              ...material,
              kdfIterations: cfg.kdfIterations,
              kdfMemory: cfg.kdfMemory,
              kdfParallelism: cfg.kdfParallelism,
            })
            console.log('Background KDF parameter upgrade succeeded!')
          } catch (err) {
            console.error('Background KDF parameter upgrade failed:', err)
          }
        })()
      }
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
      if (await checkBreach(newPassword)) {
        throw new Error('This password has been exposed in a data breach. Please choose a different password.')
      }
      const material = getCryptoMaterial()
      if (!material) throw new Error('No vault key material')

      onProgress?.(0.1)
      let oldVaultKey = vaultKeyRef.current
      if (!oldVaultKey) {
        const kek = await deriveKek(
          currentPassword,
          material.encryptionSalt,
          material.kdfIterations,
          material.kdfMemory,
          material.kdfParallelism
        )
        oldVaultKey = await unwrapVaultKey(kek, material.wrappedVaultKey)
      }

      onProgress?.(0.4)
      const newSalt = bytesToBase64(generateRandomBytes(16))
      const newKek = await deriveKek(newPassword, newSalt) // uses recommended defaults automatically
      const newWrapped = await wrapVaultKey(newKek, oldVaultKey)

      onProgress?.(0.6)
      const authSalt = material.authSalt
      if (!authSalt) throw new Error('No auth salt found. Please log in again.')
      const currentAuthHash = await derivePasswordHash(
        currentPassword,
        authSalt,
        material.kdfIterations,
        material.kdfMemory,
        material.kdfParallelism
      )
      const newAuthHash = await derivePasswordHash(newPassword, authSalt) // uses recommended defaults automatically

      onProgress?.(0.7)
      const sudo = await requestSudo(currentAuthHash)
      const sudoToken = sudo.sudoToken

      onProgress?.(0.8)
      const res = await changePassword({
        current_auth_hash: currentAuthHash,
        new_auth_hash: newAuthHash,
        wrapped_vault_key: newWrapped,
        new_encryption_salt: newSalt,
      }, sudoToken)

      setCryptoMaterial({
        authSalt: res.authSalt,
        encryptionSalt: res.encryptionSalt,
        wrappedVaultKey: res.wrappedVaultKey,
        encryptionVersion: res.encryptionVersion,
        kdfIterations: res.kdfIterations,
        kdfMemory: res.kdfMemory,
        kdfParallelism: res.kdfParallelism,
      })
      setTokens(res.accessToken)

      try {
        new BroadcastChannel(CROSS_TAB_CHANNEL).postMessage('crypto-changed')
      } catch {
      }
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
