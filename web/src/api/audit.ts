import { apiClient } from './client'

export interface AuditLogEntry {
  id: string
  action: string
  ipAddress: string
  createdAt: string
}

export interface AuditResponse {
  logs: AuditLogEntry[]
  totalPages: number
}

export function getAuditLogs(page = 0, size = 20) {
  return apiClient<AuditResponse>(`/audit?page=${page}&size=${size}`)
}
