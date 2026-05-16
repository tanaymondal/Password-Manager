import { argon2id } from 'hash-wasm'
import { base64ToBytes } from './util'

export async function deriveKek(
  password: string,
  saltBase64: string,
): Promise<CryptoKey> {
  const salt = base64ToBytes(saltBase64)

  const keyBytes = await argon2id({
    password,
    salt,
    parallelism: 4,
    iterations: 3,
    memorySize: 65536,
    hashLength: 32,
    outputType: 'binary',
  })

  return crypto.subtle.importKey('raw', keyBytes as Uint8Array<ArrayBuffer>, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ])
}
