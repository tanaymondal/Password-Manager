import { describe, it, expect } from 'vitest'
import fs from 'fs'
import path from 'path'
import {
  derivePasswordHash,
  deriveKek,
  generateSalt,
  generateVaultKey,
  unwrapVaultKey,
  wrapVaultKey,
  encryptEntry,
  decryptEntry,
  DEFAULT_KDF_ITERATIONS,
  DEFAULT_KDF_MEMORY,
  DEFAULT_KDF_PARALLELISM,
} from './cryptoCore'

function b64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

function unb64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0))
}

describe('golden vectors (cross-platform parity)', () => {
  const vectorsPath = path.resolve(__dirname, '../../../test-vectors/vectors.json')

  it('all platforms produce same auth_hash', async () => {
    const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8'))
    const v = vectors.vectors.find((v: any) => v.op === 'derive_auth_hash')
    expect(v).toBeDefined()
    const got = await derivePasswordHash(
      v.input.password,
      v.input.salt_str,
      v.params.iterations,
      v.params.memory_kib,
      v.params.parallelism
    )
    expect(got).toBe(v.expected.auth_hash_b64)
  })

  it('all platforms produce same kek', async () => {
    const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8'))
    const v = vectors.vectors.find((vv: any) => vv.op === 'derive_kek')
    expect(v).toBeDefined()
    const kek = await deriveKek(v.input.password, v.input.salt_b64, v.params.iterations, v.params.memory_kib, v.params.parallelism)
    const raw = await crypto.subtle.exportKey('raw', kek)
    const b64 = btoa(String.fromCharCode(...new Uint8Array(raw)))
    expect(b64).toBe(v.expected.kek_raw_b64)
  })

  it('all platforms can decrypt same wrapped vault key', async () => {
    const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8'))
    const v = vectors.vectors.find((vv: any) => vv.op === 'wrap_vault_key')
    expect(v).toBeDefined()
    const kekRaw = unb64(v.input.kek_raw_b64)
    const kek = await crypto.subtle.importKey('raw', kekRaw.buffer as ArrayBuffer, 'AES-GCM', true, ['encrypt', 'decrypt'])
    const unwrapped = await unwrapVaultKey(kek, v.expected.wrapped_b64)
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', unwrapped))
    expect(btoa(String.fromCharCode(...raw))).toBe(v.input.vault_key_raw_b64)
  })

  it('all platforms can decrypt same entry', async () => {
    const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8'))
    const v = vectors.vectors.find((vv: any) => vv.op === 'encrypt_entry')
    expect(v).toBeDefined()
    const vkRaw = unb64(v.input.vault_key_raw_b64)
    const vk = await crypto.subtle.importKey('raw', vkRaw.buffer as ArrayBuffer, 'AES-GCM', true, ['encrypt', 'decrypt'])
    const decrypted = await decryptEntry(vk, v.expected.encrypted_data, v.expected.iv)
    expect(decrypted).toBe(v.input.plaintext_json)
  })
})

describe('DEFAULT_KDF_*', () => {
  it('has correct default values', () => {
    expect(DEFAULT_KDF_ITERATIONS).toBe(3)
    expect(DEFAULT_KDF_MEMORY).toBe(98304)
    expect(DEFAULT_KDF_PARALLELISM).toBe(4)
  })
})

describe('derivePasswordHash', () => {
  it('produces a base64 string', async () => {
    const hash = await derivePasswordHash('testpassword', 'saltsalt1234', 3, 8192, 1)
    expect(typeof hash).toBe('string')
    expect(hash.length).toBe(44)
    // base64 of 32 bytes is always 44 chars
  })

  it('is deterministic', async () => {
    const h1 = await derivePasswordHash('test', 'saltsalt1234', 3, 8192, 1)
    const h2 = await derivePasswordHash('test', 'saltsalt1234', 3, 8192, 1)
    expect(h1).toBe(h2)
  })

  it('differs for different passwords', async () => {
    const h1 = await derivePasswordHash('password1', 'saltsalt1234', 3, 8192, 1)
    const h2 = await derivePasswordHash('password2', 'saltsalt1234', 3, 8192, 1)
    expect(h1).not.toBe(h2)
  })

  it('differs for different salts', async () => {
    const h1 = await derivePasswordHash('test', 'saltsalt1234', 3, 8192, 1)
    const h2 = await derivePasswordHash('test', 'saltsalt1111', 3, 8192, 1)
    expect(h1).not.toBe(h2)
  })

  it('works with default params', async () => {
    const hash = await derivePasswordHash('test', 'saltsalt1234')
    expect(hash.length).toBe(44)
  })
})

describe('deriveKek', () => {
  it('returns a CryptoKey', async () => {
    const salt = b64(new TextEncoder().encode('0123456789abcdef'))
    const kek = await deriveKek('testpassword', salt, 3, 8192, 1)
    expect(kek).toBeInstanceOf(CryptoKey)
    expect(kek.algorithm.name).toBe('AES-GCM')
  })

  it('is deterministic (same password + salt = same key)', async () => {
    const salt = b64(new TextEncoder().encode('0123456789abcdef'))
    const k1 = await deriveKek('test', salt, 3, 8192, 1)
    const k2 = await deriveKek('test', salt, 3, 8192, 1)
    const k1Bytes = await crypto.subtle.exportKey('raw', k1)
    const k2Bytes = await crypto.subtle.exportKey('raw', k2)
    expect(new Uint8Array(k1Bytes)).toEqual(new Uint8Array(k2Bytes))
  })

  it('with default params produces a valid AES-256 key', async () => {
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)))
    const kek = await deriveKek('test', salt)
    const raw = await crypto.subtle.exportKey('raw', kek)
    expect(raw.byteLength).toBe(32)
  })
})

describe('generateSalt', () => {
  it('returns a base64 string', () => {
    const salt = generateSalt()
    expect(typeof salt).toBe('string')
    const decoded = unb64(salt)
    expect(decoded.length).toBe(16)
  })

  it('produces unique values', () => {
    const s1 = generateSalt()
    const s2 = generateSalt()
    expect(s1).not.toBe(s2)
  })
})

describe('generateVaultKey', () => {
  it('returns an AES-GCM CryptoKey', async () => {
    const key = await generateVaultKey()
    expect(key).toBeInstanceOf(CryptoKey)
    expect(key.algorithm.name).toBe('AES-GCM')
    const raw = await crypto.subtle.exportKey('raw', key)
    expect(raw.byteLength).toBe(32)
  })

  it('produces unique keys', async () => {
    const k1 = await generateVaultKey()
    const k2 = await generateVaultKey()
    const r1 = await crypto.subtle.exportKey('raw', k1)
    const r2 = await crypto.subtle.exportKey('raw', k2)
    expect(new Uint8Array(r1)).not.toEqual(new Uint8Array(r2))
  })
})

describe('wrapVaultKey / unwrapVaultKey', () => {
  it('round-trips correctly', async () => {
    const salt = generateSalt()
    const kek = await deriveKek('password', salt)
    const vk = await generateVaultKey()
    const wrapped = await wrapVaultKey(kek, vk)
    expect(typeof wrapped).toBe('string')
    const unwrapped = await unwrapVaultKey(kek, wrapped)
    const vkRaw = await crypto.subtle.exportKey('raw', vk)
    const unwrappedRaw = await crypto.subtle.exportKey('raw', unwrapped)
    expect(new Uint8Array(unwrappedRaw)).toEqual(new Uint8Array(vkRaw))
  })

  it('wrapped key is longer than raw key (has IV prefix)', async () => {
    const salt = generateSalt()
    const kek = await deriveKek('password', salt)
    const vk = await generateVaultKey()
    const wrapped = await wrapVaultKey(kek, vk)
    const decoded = unb64(wrapped)
    expect(decoded.length).toBeGreaterThan(32)
  })

  it('produces unique wrapped output each time (random IV)', async () => {
    const salt = generateSalt()
    const kek = await deriveKek('password', salt)
    const vk = await generateVaultKey()
    const w1 = await wrapVaultKey(kek, vk)
    const w2 = await wrapVaultKey(kek, vk)
    expect(w1).not.toBe(w2)
  })

  it('rejects wrong KEK', async () => {
    const salt1 = generateSalt()
    const salt2 = generateSalt()
    const kek1 = await deriveKek('password1', salt1)
    const kek2 = await deriveKek('password2', salt2)
    const vk = await generateVaultKey()
    const wrapped = await wrapVaultKey(kek1, vk)
    await expect(unwrapVaultKey(kek2, wrapped)).rejects.toThrow()
  })

  it('rejects tampered wrapped key', async () => {
    const salt = generateSalt()
    const kek = await deriveKek('password', salt)
    const vk = await generateVaultKey()
    const wrapped = await wrapVaultKey(kek, vk)
    const decoded = unb64(wrapped)
    decoded[decoded.length - 1] ^= 1
    const tampered = b64(decoded)
    await expect(unwrapVaultKey(kek, tampered)).rejects.toThrow()
  })

  it('rejects garbage input', async () => {
    const salt = generateSalt()
    const kek = await deriveKek('password', salt)
    await expect(unwrapVaultKey(kek, '!!!invalid-base64!!!')).rejects.toThrow()
  })
})

describe('encryptEntry / decryptEntry', () => {
  it('encrypted data has v1: prefix', async () => {
    const vk = await generateVaultKey()
    const result = await encryptEntry(vk, 'test')
    expect(result.encryptedData.startsWith('v1:')).toBe(true)
    expect(typeof result.iv).toBe('string')
  })

  it('round-trips correctly', async () => {
    const vk = await generateVaultKey()
    const plaintext = JSON.stringify({ username: 'alice', password: 'hunter2' })
    const encrypted = await encryptEntry(vk, plaintext)
    const decrypted = await decryptEntry(vk, encrypted.encryptedData, encrypted.iv)
    expect(decrypted).toBe(plaintext)
  })

  it('round-trips JSON with special characters', async () => {
    const vk = await generateVaultKey()
    const plaintext = JSON.stringify({
      name: 'test@example.com',
      url: 'https://example.com/path?q=1&r=2',
      notes: 'line1\nline2\ttab',
    })
    const encrypted = await encryptEntry(vk, plaintext)
    const decrypted = await decryptEntry(vk, encrypted.encryptedData, encrypted.iv)
    expect(decrypted).toBe(plaintext)
  })

  it('produces different ciphertext each time (random IV)', async () => {
    const vk = await generateVaultKey()
    const plaintext = 'hello'
    const e1 = await encryptEntry(vk, plaintext)
    const e2 = await encryptEntry(vk, plaintext)
    expect(e1.encryptedData).not.toBe(e2.encryptedData)
    expect(e1.iv).not.toBe(e2.iv)
  })

  it('rejects wrong vault key', async () => {
    const vk1 = await generateVaultKey()
    const vk2 = await generateVaultKey()
    const encrypted = await encryptEntry(vk1, 'secret')
    await expect(decryptEntry(vk2, encrypted.encryptedData, encrypted.iv)).rejects.toThrow()
  })

  it('rejects tampered encrypted data', async () => {
    const vk = await generateVaultKey()
    const encrypted = await encryptEntry(vk, 'secret')
    const data = encrypted.encryptedData
    const bytes = unb64(data.slice(3))
    bytes[bytes.length - 1] ^= 1
    const tampered = 'v1:' + b64(bytes)
    await expect(decryptEntry(vk, tampered, encrypted.iv)).rejects.toThrow()
  })

  it('rejects tampered IV', async () => {
    const vk = await generateVaultKey()
    const encrypted = await encryptEntry(vk, 'secret')
    const ivBytes = unb64(encrypted.iv)
    ivBytes[0] ^= 1
    const tamperedIv = b64(ivBytes)
    await expect(decryptEntry(vk, encrypted.encryptedData, tamperedIv)).rejects.toThrow()
  })

  it('handles empty strings', async () => {
    const vk = await generateVaultKey()
    const encrypted = await encryptEntry(vk, '')
    const decrypted = await decryptEntry(vk, encrypted.encryptedData, encrypted.iv)
    expect(decrypted).toBe('')
  })
})
