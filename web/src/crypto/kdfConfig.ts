import { apiClient } from '../api/client'

export interface KdfConfig {
  kdfIterations: number
  kdfMemory: number
  kdfParallelism: number
  encryptionVersion: number
}

// Hardcoded fallback values (used when server is unreachable)
const FALLBACK: KdfConfig = {
  kdfIterations: 3,
  kdfMemory: 98304,
  kdfParallelism: 4,
  encryptionVersion: 2,
}

let cachedConfig: KdfConfig | null = null
let fetchPromise: Promise<KdfConfig> | null = null

export async function getKdfConfig(): Promise<KdfConfig> {
  if (cachedConfig) return cachedConfig
  if (fetchPromise) return fetchPromise

  fetchPromise = (async () => {
    try {
      const res = await apiClient<{ data: KdfConfig }>('/auth/kdf-config', {
        method: 'GET',
      })
      cachedConfig = res.data
      return res.data
    } catch {
      console.warn('Failed to fetch KDF config from server, using fallback')
      cachedConfig = FALLBACK
      return FALLBACK
    }
  })()

  return fetchPromise
}
