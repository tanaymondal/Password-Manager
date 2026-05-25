import { argon2id } from 'hash-wasm'
import { base64ToBytes, bytesToBase64 } from './util'

export async function derivePasswordHash(password: string, saltBase64: string): Promise<string> {
  const salt = base64ToBytes(saltBase64)
  const hashBytes = await argon2id({
    password,
    salt,
    parallelism: 4,
    iterations: 4,
    memorySize: 65536,
    hashLength: 32,
    outputType: 'binary',
  })
  return bytesToBase64(hashBytes as Uint8Array)
}

export async function deriveKek(password: string, saltBase64: string): Promise<CryptoKey> {
  const salt = base64ToBytes(saltBase64)
  const keyBytes = await argon2id({
    password,
    salt,
    parallelism: 4,
    iterations: 4,
    memorySize: 65536,
    hashLength: 32,
    outputType: 'binary',
  })
  return crypto.subtle.importKey('raw', keyBytes as Uint8Array, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ])
}
