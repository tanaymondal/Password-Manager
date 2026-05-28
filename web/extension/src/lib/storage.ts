const CRYPTO_KEY = 'crypto_material'
const TOKENS_KEY = 'auth_tokens'
const WRAPPED_KEY_SESSION = 'wrapped_vault_key'
const WRAPPING_KEY_SEED = 'vault_wrapping_seed'

export interface CryptoMaterial {
  authSalt: string
  encryptionSalt: string
  wrappedVaultKey: string
  encryptionVersion: number
  email: string
}

export interface TokenStore {
  accessToken: string
  refreshToken: string
}

export async function getCryptoMaterial(): Promise<CryptoMaterial | null> {
  const result = await chrome.storage.local.get(CRYPTO_KEY)
  return result[CRYPTO_KEY] || null
}

export async function setCryptoMaterial(data: CryptoMaterial): Promise<void> {
  await chrome.storage.local.set({ [CRYPTO_KEY]: data })
}

export async function clearCryptoMaterial(): Promise<void> {
  await chrome.storage.local.remove(CRYPTO_KEY)
}

export async function getTokens(): Promise<TokenStore | null> {
  const result = await chrome.storage.local.get(TOKENS_KEY)
  return result[TOKENS_KEY] || null
}

export async function setTokens(tokens: TokenStore): Promise<void> {
  await chrome.storage.local.set({ [TOKENS_KEY]: tokens })
}

export async function clearTokens(): Promise<void> {
  await chrome.storage.local.remove(TOKENS_KEY)
}

export async function clearAll(): Promise<void> {
  await chrome.storage.local.remove([CRYPTO_KEY, TOKENS_KEY])
  await chrome.storage.session.remove([WRAPPED_KEY_SESSION, WRAPPING_KEY_SEED])
}

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export async function persistVaultKey(vaultKey: CryptoKey): Promise<void> {
  const seed = crypto.getRandomValues(new Uint8Array(32))
  const wrappingKey = await crypto.subtle.importKey('raw', seed, 'AES-GCM', true, ['wrapKey', 'unwrapKey'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const wrapped = await crypto.subtle.wrapKey('raw', vaultKey, wrappingKey, { name: 'AES-GCM', iv, tagLength: 128 })
  const combined = new Uint8Array(iv.length + wrapped.byteLength)
  combined.set(iv, 0)
  combined.set(new Uint8Array(wrapped), iv.length)
  await chrome.storage.session.set({
    [WRAPPED_KEY_SESSION]: bytesToBase64(combined),
    [WRAPPING_KEY_SEED]: bytesToBase64(seed),
  })
}

export async function restoreVaultKey(): Promise<CryptoKey | null> {
  const result = await chrome.storage.session.get([WRAPPED_KEY_SESSION, WRAPPING_KEY_SEED])
  if (!result[WRAPPED_KEY_SESSION] || !result[WRAPPING_KEY_SEED]) return null
  const seed = base64ToBytes(result[WRAPPING_KEY_SEED])
  const combined = base64ToBytes(result[WRAPPED_KEY_SESSION])
  const iv = combined.slice(0, 12)
  const wrapped = combined.slice(12)
  const wrappingKey = await crypto.subtle.importKey('raw', seed, 'AES-GCM', true, ['wrapKey', 'unwrapKey'])
  return crypto.subtle.unwrapKey('raw', wrapped, wrappingKey, { name: 'AES-GCM', iv, tagLength: 128 }, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

export async function clearVaultKey(): Promise<void> {
  await chrome.storage.session.remove([WRAPPED_KEY_SESSION, WRAPPING_KEY_SEED])
}
