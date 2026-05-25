import { base64ToBytes, bytesToBase64 } from './util'

export interface EncryptedPayload {
  encryptedData: string
  iv: string
}

export interface EntryFields {
  name: string
  username: string
  password: string
  url: string
  notes: string
}

export async function decryptEntry(
  vaultKey: CryptoKey,
  encryptedData: string,
  ivBase64: string,
): Promise<string> {
  const ciphertext = base64ToBytes(encryptedData)
  const iv = base64ToBytes(ivBase64)

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    vaultKey,
    ciphertext,
  )

  return new TextDecoder().decode(plaintext)
}

export function parseEntryFields(json: string): EntryFields {
  const data = JSON.parse(json)
  return {
    name: data.name || '',
    username: data.username || '',
    password: data.password || '',
    url: data.url || '',
    notes: data.notes || '',
  }
}
