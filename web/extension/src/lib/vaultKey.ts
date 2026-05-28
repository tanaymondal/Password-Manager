import { base64ToBytes } from './util'

export async function unwrapVaultKeyBytes(kek: CryptoKey, wrappedVaultKeyBase64: string): Promise<Uint8Array> {
  const combined = base64ToBytes(wrappedVaultKeyBase64)
  const iv = combined.slice(0, 12)
  const ciphertext = combined.slice(12)

  const vaultKeyBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    kek,
    ciphertext,
  )

  return new Uint8Array(vaultKeyBytes)
}

export function importVaultKey(rawBytes: Uint8Array, extractable = false): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', rawBytes, 'AES-GCM', extractable, [
    'encrypt',
    'decrypt',
  ])
}

export async function unwrapVaultKey(kek: CryptoKey, wrappedVaultKeyBase64: string): Promise<CryptoKey> {
  const bytes = await unwrapVaultKeyBytes(kek, wrappedVaultKeyBase64)
  return importVaultKey(bytes, true)
}
