export interface CryptoMaterial {
  authSalt: string
  encryptionSalt: string
  wrappedVaultKey: string
  encryptionVersion: number
}

let _cryptoMaterial: CryptoMaterial | null = null
let _autoUnlockVaultKey: CryptoKey | null = null

export function getCryptoMaterial(): CryptoMaterial | null {
  return _cryptoMaterial
}

export function setCryptoMaterial(data: CryptoMaterial | null) {
  _cryptoMaterial = data
}

export function consumeAutoUnlockVaultKey(): CryptoKey | null {
  const key = _autoUnlockVaultKey
  _autoUnlockVaultKey = null
  return key
}

export function setAutoUnlockVaultKey(key: CryptoKey | null) {
  _autoUnlockVaultKey = key
}

export function clearAll() {
  _cryptoMaterial = null
  _autoUnlockVaultKey = null
}
