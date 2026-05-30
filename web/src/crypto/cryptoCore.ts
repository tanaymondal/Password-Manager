import init, {
  WasmKdfParams,
  wasm_derive_master_key,
  wasm_derive_auth_hash,
  wasm_derive_kek,
  wasm_wrap_vault_key,
  wasm_unwrap_vault_key,
  wasm_encrypt_entry,
  wasm_decrypt_entry,
} from './wasm/securevault_crypto_core'
import { getKdfConfig } from './kdfConfig'

let initialized = false

async function ensureInit() {
  if (!initialized) {
    await init()
    initialized = true
  }
}

function b64(uk: Uint8Array): string {
  return btoa(String.fromCharCode(...uk))
}

function unb64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0))
}

// Hardcoded fallbacks — used when server is unreachable
export const DEFAULT_KDF_ITERATIONS = 3
export const DEFAULT_KDF_MEMORY = 98304
export const DEFAULT_KDF_PARALLELISM = 4

async function resolveParams(
  iterations?: number,
  memorySize?: number,
  parallelism?: number,
): Promise<{ iterations: number; memorySize: number; parallelism: number }> {
  if (iterations !== undefined) return { iterations, memorySize: memorySize!, parallelism: parallelism! }
  const cfg = await getKdfConfig()
  return { iterations: cfg.kdfIterations, memorySize: cfg.kdfMemory, parallelism: cfg.kdfParallelism }
}

// Single Argon2id call — derive master key
async function deriveMasterKey(
  password: string,
  saltBase64: string,
  iterations?: number,
  memorySize?: number,
  parallelism?: number,
): Promise<string> {
  await ensureInit()
  const p = await resolveParams(iterations, memorySize, parallelism)
  const wp = new WasmKdfParams(p.iterations, p.memorySize, p.parallelism)
  return wasm_derive_master_key(password, saltBase64, wp)
}

// Derive auth hash from master key (SHA256(masterKey || "securevault-auth"))
export async function derivePasswordHash(
  password: string,
  salt: string,
  iterations?: number,
  memorySize?: number,
  parallelism?: number,
): Promise<string> {
  const mkB64 = await deriveMasterKey(password, salt, iterations, memorySize, parallelism)
  return wasm_derive_auth_hash(mkB64)
}

// Derive KEK from master key (SHA256(masterKey || "securevault-kek"))
export async function deriveKek(
  password: string,
  saltBase64: string,
  iterations?: number,
  memorySize?: number,
  parallelism?: number,
): Promise<CryptoKey> {
  const mkB64 = await deriveMasterKey(password, saltBase64, iterations, memorySize, parallelism)
  const kekB64 = wasm_derive_kek(mkB64)
  return crypto.subtle.importKey('raw', unb64(kekB64).buffer as ArrayBuffer, 'AES-GCM', true, ['encrypt', 'decrypt'])
}

export function generateSalt(): string {
  return b64(crypto.getRandomValues(new Uint8Array(16)))
}

export async function generateVaultKey(): Promise<CryptoKey> {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32))
  return crypto.subtle.importKey('raw', keyBytes.buffer as ArrayBuffer, 'AES-GCM', true, ['encrypt', 'decrypt'])
}

export async function unwrapVaultKey(
  kek: CryptoKey,
  wrappedVaultKeyBase64: string,
): Promise<CryptoKey> {
  await ensureInit()
  const kekB64 = b64(new Uint8Array(await crypto.subtle.exportKey('raw', kek)))
  const vkB64 = wasm_unwrap_vault_key(kekB64, wrappedVaultKeyBase64)
  return crypto.subtle.importKey('raw', unb64(vkB64).buffer as ArrayBuffer, 'AES-GCM', true, ['encrypt', 'decrypt'])
}

export async function wrapVaultKey(
  kek: CryptoKey,
  vaultKey: CryptoKey,
): Promise<string> {
  await ensureInit()
  const kekRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kek))
  const vkRaw = new Uint8Array(await crypto.subtle.exportKey('raw', vaultKey))
  return wasm_wrap_vault_key(b64(kekRaw), b64(vkRaw))
}

export interface EncryptedPayload {
  encryptedData: string
  iv: string
}

export async function encryptEntry(
  vaultKey: CryptoKey,
  plaintext: string,
): Promise<EncryptedPayload> {
  await ensureInit()
  const vkB64 = b64(new Uint8Array(await crypto.subtle.exportKey('raw', vaultKey)))
  return JSON.parse(wasm_encrypt_entry(vkB64, plaintext))
}

export async function decryptEntry(
  vaultKey: CryptoKey,
  encryptedData: string,
  ivBase64: string,
): Promise<string> {
  await ensureInit()
  const vkB64 = b64(new Uint8Array(await crypto.subtle.exportKey('raw', vaultKey)))
  return wasm_decrypt_entry(vkB64, encryptedData, ivBase64)
}
