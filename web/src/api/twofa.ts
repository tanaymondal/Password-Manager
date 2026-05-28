import { apiClient } from './client'

export interface TwoFactorSetupResponse {
  secret: string
  qrCodeUrl: string
}

export interface TwoFactorStatusResponse {
  enabled: boolean
}

export function get2FAStatus() {
  return apiClient<TwoFactorStatusResponse>('/2fa/status')
}

export function setup2FA() {
  return apiClient<TwoFactorSetupResponse>('/2fa/setup')
}

export function enable2FA(code: string) {
  return apiClient<void>('/2fa/enable', {
    method: 'POST',
    body: JSON.stringify({ code }),
  })
}

export function disable2FA(code: string, sudoToken?: string) {
  const headers: Record<string, string> = {}
  if (sudoToken) headers['X-Sudo-Token'] = sudoToken
  return apiClient<void>('/2fa/disable', {
    method: 'POST',
    body: JSON.stringify({ code }),
    headers,
  })
}
