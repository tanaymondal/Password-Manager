import { base64ToBytes } from './util'

export async function unwrapVaultKey(kek: CryptoKey, wrappedVaultKeyBase64: string): Promise<CryptoKey> {
  const combined = base64ToBytes(wrappedVaultKeyBase64)
  const iv = combined.slice(0, 12)
  const ciphertext = combined.slice(12)

  const vaultKeyBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    kek,
    ciphertext,
  )

  return crypto.subtle.importKey('raw', new Uint8Array(vaultKeyBytes), 'AES-GCM', true, [
    'encrypt',
    'decrypt',
  ])
}
