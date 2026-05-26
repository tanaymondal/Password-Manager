const CRYPTO_KEY = 'crypto_material'
const TOKENS_KEY = 'auth_tokens'
const VAULT_KEY_SESSION = 'vault_key_bytes'

export interface CryptoMaterial {
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
  await chrome.storage.session.remove(VAULT_KEY_SESSION)
}

export async function setVaultKeyBytes(bytes: Uint8Array): Promise<void> {
  const base64 = btoa(String.fromCharCode(...bytes))
  await chrome.storage.session.set({ [VAULT_KEY_SESSION]: base64 })
}

export async function getVaultKeyBytes(): Promise<Uint8Array | null> {
  const result = await chrome.storage.session.get(VAULT_KEY_SESSION)
  const base64 = result[VAULT_KEY_SESSION]
  if (!base64) return null
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export async function clearVaultKeyBytes(): Promise<void> {
  await chrome.storage.session.remove(VAULT_KEY_SESSION)
}
