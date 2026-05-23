import { base64ToBytes, bytesToBase64, generateRandomBytes } from './util'

export async function unwrapVaultKey(
  kek: CryptoKey,
  wrappedVaultKeyBase64: string,
): Promise<CryptoKey> {
  const combined = base64ToBytes(wrappedVaultKeyBase64)
  const iv = combined.slice(0, 12) as Uint8Array<ArrayBuffer>
  const ciphertext = combined.slice(12) as Uint8Array<ArrayBuffer>

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

export async function wrapVaultKey(
  kek: CryptoKey,
  vaultKey: CryptoKey,
): Promise<string> {
  const vaultKeyRaw = await crypto.subtle.exportKey('raw', vaultKey)
  const iv = generateRandomBytes(12) as Uint8Array<ArrayBuffer>

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    kek,
    vaultKeyRaw,
  )

  const combined = new Uint8Array(12 + ciphertext.byteLength)
  combined.set(iv, 0)
  combined.set(new Uint8Array(ciphertext), 12)

  return bytesToBase64(combined)
}
