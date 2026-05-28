import { argon2id } from 'hash-wasm'
import { base64ToBytes, bytesToBase64, generateRandomBytes } from './util'

export const DEFAULT_KDF_ITERATIONS = 4
export const DEFAULT_KDF_MEMORY = 65536 // 64MB in KiB
export const DEFAULT_KDF_PARALLELISM = 4

export async function derivePasswordHash(
  password: string,
  salt: string,
  iterations: number = DEFAULT_KDF_ITERATIONS,
  memorySize: number = DEFAULT_KDF_MEMORY,
  parallelism: number = DEFAULT_KDF_PARALLELISM,
): Promise<string> {
  const saltBytes = new TextEncoder().encode(salt)

  const hashBytes = await argon2id({
    password,
    salt: saltBytes,
    parallelism,
    iterations,
    memorySize,
    hashLength: 32,
    outputType: 'binary',
  })

  return bytesToBase64(hashBytes as Uint8Array<ArrayBuffer>)
}

export async function deriveKek(
  password: string,
  saltBase64: string,
  iterations: number = DEFAULT_KDF_ITERATIONS,
  memorySize: number = DEFAULT_KDF_MEMORY,
  parallelism: number = DEFAULT_KDF_PARALLELISM,
): Promise<CryptoKey> {
  const salt = base64ToBytes(saltBase64)

  const keyBytes = await argon2id({
    password,
    salt,
    parallelism,
    iterations,
    memorySize,
    hashLength: 32,
    outputType: 'binary',
  })

  return crypto.subtle.importKey('raw', keyBytes as Uint8Array<ArrayBuffer>, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ])
}

export function generateSalt(): string {
  return bytesToBase64(generateRandomBytes(16))
}

export async function generateVaultKey(): Promise<CryptoKey> {
  const keyBytes = generateRandomBytes(32)
  return crypto.subtle.importKey('raw', keyBytes as Uint8Array<ArrayBuffer>, 'AES-GCM', true, [
    'encrypt',
    'decrypt',
  ])
}
