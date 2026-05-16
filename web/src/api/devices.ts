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

export function deleteDevice(id: string) {
  return apiClient<void>(`/devices/${id}`, { method: 'DELETE' })
}
