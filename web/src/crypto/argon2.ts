import {
  derivePasswordHash as dp,
  deriveKek as dk,
  generateSalt as gs,
  generateVaultKey as gvk,
  DEFAULT_KDF_ITERATIONS,
  DEFAULT_KDF_MEMORY,
  DEFAULT_KDF_PARALLELISM,
} from './cryptoCore'

export const derivePasswordHash = dp
export const deriveKek = dk
export const generateSalt = gs
export const generateVaultKey = gvk
export { DEFAULT_KDF_ITERATIONS, DEFAULT_KDF_MEMORY, DEFAULT_KDF_PARALLELISM }
