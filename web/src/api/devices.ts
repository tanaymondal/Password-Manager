import { apiClient } from './client'

export interface DeviceResponse {
  id: string
  deviceName: string
  deviceId: string
  lastAccessedAt: string
  createdAt: string
}

export interface DevicesResponse {
  devices: DeviceResponse[]
  count: number
}

export function getDevices() {
  return apiClient<DevicesResponse>('/devices')
}

export function deleteDevice(id: string, sudoToken?: string) {
  const headers: Record<string, string> = {}
  if (sudoToken) headers['X-Sudo-Token'] = sudoToken
  return apiClient<void>(`/devices/${id}`, { method: 'DELETE', headers })
}
