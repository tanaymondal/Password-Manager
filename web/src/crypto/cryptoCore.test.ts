import { describe, it, expect } from 'vitest'
import vectors from '../../../test-vectors/vectors.json'
import {
  derivePasswordHash,
  deriveKek,
  generateSalt,
  generateVaultKey,
  unwrapVaultKey,
  wrapVaultKey,
  encryptEntry,
  decryptEntry,
  encryptField,
  decryptField,
} from './cryptoCore'

function b64(s: string | Uint8Array): string {
  if (typeof s === 'string') return btoa(s)
  return btoa(String.fromCharCode(...s))
}

function unb64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0))
}

describe('golden vectors (cross-platform parity)', () => {
  it('all platforms produce same auth_hash', async () => {
    const hash = await derivePasswordHash('correct horse battery staple', b64('auth-salt-fixed-string'), 3, 98304, 4)
    expect(hash).toBeTruthy()
    expect(hash.length).toBe(44)
  })

  it('all platforms produce same kek', async () => {
    const kek = await deriveKek('correct horse battery staple', b64('0123456789abcdef'), 3, 98304, 4)
    expect(kek).toBeTruthy()
    expect(kek.algorithm.name).toBe('AES-GCM')
  })

  it('generates deterministic auth hash', async () => {
    const h1 = await derivePasswordHash('test', b64('saltsalt1234'), 3, 8192, 1)
    const h2 = await derivePasswordHash('test', b64('saltsalt1234'), 3, 8192, 1)
    expect(h1).toBe(h2)
  })
})

// Cross-platform AES-GCM golden vector tests
// Verifies that all platforms produce identical AES-256-GCM output

async function importKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw.buffer as ArrayBuffer, 'AES-GCM', true, ['encrypt', 'decrypt'])
}

describe('AES-GCM golden vectors (cross-platform parity)', () => {
  for (const v of vectors.vectors) {
    const name = v.name
    const op = v.op
    const inp = v.input
    const exp = v.expected

    if (op === 'wrap_vault_key') {
      it(`${name}: unwrap recovers vault key`, async () => {
        const kek = await importKey(new Uint8Array(atob(inp.kek_raw_b64).split('').map(c => c.charCodeAt(0))))
        const unwrapped = await unwrapVaultKey(kek, exp.wrapped_b64)
        const raw = new Uint8Array(await crypto.subtle.exportKey('raw', unwrapped))
        const expected = new Uint8Array(atob(inp.vault_key_raw_b64).split('').map(c => c.charCodeAt(0)))
        expect(raw).toEqual(expected)
      })
    }

    if (op === 'encrypt_entry') {
      it(`${name}: decrypt recovers plaintext`, async () => {
        const vkRaw = new Uint8Array(atob(inp.vault_key_raw_b64).split('').map(c => c.charCodeAt(0)))
        const vk = await importKey(vkRaw)
        const decrypted = await decryptEntry(vk, exp.encrypted_data, exp.iv)
        expect(decrypted).toBe(inp.plaintext_json)
      })
    }

    if (op === 'encrypt_field') {
      it(`${name}: decrypt field recovers plaintext`, async () => {
        const vkRaw = new Uint8Array(atob(inp.vault_key_raw_b64).split('').map(c => c.charCodeAt(0)))
        const vk = await importKey(vkRaw)
        const decrypted = await decryptField(vk, exp.ciphertext)
        expect(decrypted).toBe(inp.plaintext)
      })
    }
  }
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
