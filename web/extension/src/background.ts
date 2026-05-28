import { derivePasswordHash, deriveKek } from './lib/argon2'
import { unwrapVaultKey } from './lib/vaultKey'
import { decryptEntry, parseEntryFields, type EntryFields } from './lib/entries'
import {
  getCryptoMaterial, setCryptoMaterial, clearCryptoMaterial,
  getTokens, setTokens, clearTokens, clearAll,
  setVaultKeyBytes, getVaultKeyBytes, clearVaultKeyBytes,
  type CryptoMaterial,
} from './lib/storage'
import { apiLogin, apiPrelogin, apiGetVaultEntries, apiLogout, verifyTwoFactor } from './lib/api'

let vaultKey: CryptoKey | null = null
let cachedEntries: { id: string; fields: EntryFields }[] = []
let currentEmail: string = ''

chrome.runtime.onInstalled.addListener(async () => {
  const bytes = await getVaultKeyBytes()
  if (bytes) {
    vaultKey = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', true, ['encrypt', 'decrypt'])
  }
})

async function ensureVaultKey(): Promise<boolean> {
  if (vaultKey) return true
  const bytes = await getVaultKeyBytes()
  if (bytes) {
    vaultKey = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', true, ['encrypt', 'decrypt'])
    return true
  }
  return false
}

async function fetchAndCacheEntries() {
  if (!vaultKey) return
  const res = await apiGetVaultEntries()
  cachedEntries = []
  for (const entry of res.entries) {
    try {
      const plaintext = await decryptEntry(vaultKey, entry.encryptedData, entry.iv)
      const fields = parseEntryFields(plaintext)
      cachedEntries.push({ id: entry.id, fields })
    } catch {
      // skip entries that fail to decrypt
    }
  }
}

function getDomain(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '')
  } catch {
    return url
  }
}

chrome.runtime.onMessage.addListener((message: any, sender: chrome.runtime.MessageSender, sendResponse: (response: any) => void) => {
  handleMessage(message, sender).then(sendResponse)
  return true
})

async function handleVerifySuccess(res: {
  authSalt: string
  encryptionSalt: string
  wrappedVaultKey: string
  encryptionVersion: number
  accessToken: string
  refreshToken: string
}, password: string, email: string): Promise<{ success: true }> {
  const cm: CryptoMaterial = {
    authSalt: res.authSalt,
    encryptionSalt: res.encryptionSalt,
    wrappedVaultKey: res.wrappedVaultKey,
    encryptionVersion: res.encryptionVersion,
    email,
  }

  await setCryptoMaterial(cm)
  await setTokens({ accessToken: res.accessToken, refreshToken: res.refreshToken })

  const kek = await deriveKek(password, cm.encryptionSalt)
  vaultKey = await unwrapVaultKey(kek, cm.wrappedVaultKey)

  const rawKey = await crypto.subtle.exportKey('raw', vaultKey)
  await setVaultKeyBytes(new Uint8Array(rawKey))

  currentEmail = email
  await fetchAndCacheEntries()

  return { success: true }
}

async function handleMessage(message: any, sender: chrome.runtime.MessageSender): Promise<any> {
  switch (message.type) {
    case 'login': {
      try {
        const { email, password } = message
        const pre = await apiPrelogin(email)
        const authHash = await derivePasswordHash(password, pre.authSalt)
        const loginRes = await apiLogin({
          email,
          authHash,
          deviceName: 'Browser Extension',
          deviceId: crypto.randomUUID(),
        })

        if (loginRes.twoFactorMethods?.length) {
          return { success: false, error: '2fa_required', challengeId: loginRes.challengeId, email }
        }

        const verifyRes = await verifyTwoFactor(email, loginRes.challengeId)
        return await handleVerifySuccess(verifyRes, password, email)
      } catch (error: any) {
        return { success: false, error: error.message || 'Login failed' }
      }
    }

    case 'verify2fa': {
      try {
        const { email, password, challengeId, code } = message
        const res = await verifyTwoFactor(email, challengeId, code)
        return await handleVerifySuccess(res, password, email)
      } catch (error: any) {
        return { success: false, error: error.message || '2FA verification failed' }
      }
    }

    case 'unlock': {
      try {
        const { password } = message
        const cm = await getCryptoMaterial()
        if (!cm) return { success: false, error: 'Not logged in. Please login first.' }

        const kek = await deriveKek(password, cm.encryptionSalt)
        vaultKey = await unwrapVaultKey(kek, cm.wrappedVaultKey)

        const rawKey = await crypto.subtle.exportKey('raw', vaultKey)
        await setVaultKeyBytes(new Uint8Array(rawKey))

        currentEmail = cm.email
        await fetchAndCacheEntries()

        return { success: true }
      } catch (error: any) {
        return { success: false, error: error.message || 'Incorrect password' }
      }
    }

    case 'logout': {
      vaultKey = null
      cachedEntries = []
      currentEmail = ''
      await clearVaultKeyBytes()
      await apiLogout()
      await clearAll()
      return { success: true }
    }

    case 'getStatus': {
      const tokens = await getTokens()
      const cm = await getCryptoMaterial()
      const isUnlocked = await ensureVaultKey()
      return {
        isAuthenticated: !!tokens,
        isUnlocked,
        email: cm?.email || null,
      }
    }

    case 'searchEntries': {
      const { query } = message
      if (!await ensureVaultKey()) return { entries: [] }
      if (cachedEntries.length === 0) {
        try { await fetchAndCacheEntries() } catch { return { entries: [] } }
      }
      const q = query.toLowerCase()
      const filtered = cachedEntries.filter(e =>
        e.fields.name.toLowerCase().includes(q) ||
        e.fields.username.toLowerCase().includes(q) ||
        e.fields.url.toLowerCase().includes(q)
      )
      return { entries: filtered }
    }

    case 'getEntriesForUrl': {
      const { url } = message
      if (!await ensureVaultKey()) return { entries: [] }
      if (cachedEntries.length === 0) {
        try { await fetchAndCacheEntries() } catch { return { entries: [] } }
      }
      const domain = getDomain(url)
      const matched = cachedEntries.filter(e => {
        try { return getDomain(e.fields.url) === domain } catch { return false }
      })
      return { entries: matched }
    }

    case 'copyToClipboard': {
      const { text } = message
      try {
        await navigator.clipboard.writeText(text)
        return { success: true }
      } catch {
        return { success: false, error: 'Failed to copy' }
      }
    }

    default:
      return { error: 'Unknown message type' }
  }
}
