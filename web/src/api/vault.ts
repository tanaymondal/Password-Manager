import { apiClient } from './client'

export interface VaultEntryResponse {
  id: string
  encryptedData: string
  iv: string
  version: number
  createdAt: string
  updatedAt: string
}

export interface VaultEntriesResponse {
  entries: VaultEntryResponse[]
  count: number
}

export interface VaultEntryRequest {
  encryptedData: string
  iv: string
}

export function getVaultEntries() {
  return apiClient<VaultEntriesResponse>('/vault')
}

export function createVaultEntry(data: VaultEntryRequest) {
  return apiClient<VaultEntryResponse>('/vault', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export function getVaultEntry(id: string) {
  return apiClient<VaultEntryResponse>(`/vault/${id}`)
}

export function updateVaultEntry(id: string, data: VaultEntryRequest) {
  return apiClient<VaultEntryResponse>(`/vault/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  })
}

export function deleteVaultEntry(id: string) {
  return apiClient<void>(`/vault/${id}`, { method: 'DELETE' })
}

export function deleteAllVaultEntries() {
  return apiClient<void>('/vault', { method: 'DELETE' })
}
