import { base64ToBytes, bytesToBase64, generateRandomBytes } from './util'

export interface EncryptedPayload {
  encryptedData: string
  iv: string
}

export async function encryptEntry(
  vaultKey: CryptoKey,
  plaintext: string,
): Promise<EncryptedPayload> {
  const iv = generateRandomBytes(12) as Uint8Array<ArrayBuffer>
  const encoded = new TextEncoder().encode(plaintext) as Uint8Array<ArrayBuffer>

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    vaultKey,
    encoded,
  )

  return {
    encryptedData: bytesToBase64(new Uint8Array(ciphertext)),
    iv: bytesToBase64(iv),
  }
}

export async function decryptEntry(
  vaultKey: CryptoKey,
  encryptedData: string,
  ivBase64: string,
): Promise<string> {
  const ciphertext = base64ToBytes(encryptedData) as Uint8Array<ArrayBuffer>
  const iv = base64ToBytes(ivBase64) as Uint8Array<ArrayBuffer>

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    vaultKey,
    ciphertext,
  )

  return new TextDecoder().decode(plaintext)
}
