import { useState, useEffect, useCallback } from 'react'
import { useVault } from '../context/VaultContext'
import { get2FAStatus, setup2FA, enable2FA, disable2FA } from '../api/twofa'
import { getDevices, deleteDevice, type DeviceResponse } from '../api/devices'
import { getAuditLogs, type AuditLogEntry } from '../api/audit'
import { generatePassword } from '../crypto/generator'
import { PasswordStrengthBar } from '../components/PasswordStrength'
import { LoadingSpinner } from '../components/LoadingSpinner'
import QRCode from 'qrcode'

type Tab = 'security' | '2fa' | 'devices' | 'audit'

const TABS: { value: Tab; label: string }[] = [
  { value: 'security', label: 'Security' },
  { value: '2fa', label: 'Two-Factor Auth' },
  { value: 'devices', label: 'Devices' },
  { value: 'audit', label: 'Audit Log' },
]

export function SettingsPage() {
  const [tab, setTab] = useState<Tab>('security')

  return (
    <div className="mx-auto max-w-3xl p-6">
      <h1 className="text-xl font-bold mb-6">Settings</h1>

      <div className="flex gap-1 mb-6 border-b border-gray-800">
        {TABS.map((t) => (
          <button
            key={t.value}
            onClick={() => setTab(t.value)}
            className={`px-4 py-2 text-sm border-b-2 -mb-px transition-colors ${
              tab === t.value
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'security' && <SecuritySection />}
      {tab === '2fa' && <TwoFactorSection />}
      {tab === 'devices' && <DevicesSection />}
      {tab === 'audit' && <AuditSection />}
    </div>
  )
}

function SecuritySection() {
  const { changeMasterPassword } = useVault()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      return
    }
    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters')
      return
    }

    setSubmitting(true)
    try {
      await changeMasterPassword(currentPassword, newPassword)
      setSuccess('Password changed successfully')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to change password')
    } finally {
      setSubmitting(false)
    }
  }

  const generate = () => {
    const pw = generatePassword({
      length: 24,
      includeUppercase: true,
      includeLowercase: true,
      includeNumbers: true,
      includeSymbols: true,
      excludeAmbiguous: true,
    })
    setNewPassword(pw)
    setConfirmPassword(pw)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4 max-w-md">
      <div>
        <label className="block text-sm font-medium text-gray-300">
          Current password
        </label>
        <input
          type="password"
          value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)}
          className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
          required
        />
      </div>

      <div>
        <div className="flex items-center justify-between">
          <label className="block text-sm font-medium text-gray-300">
            New password
          </label>
          <button
            type="button"
            onClick={generate}
            className="text-xs text-emerald-400 hover:text-emerald-300"
          >
            Generate
          </button>
        </div>
        <div className="relative mt-1">
          <input
            type={showPassword ? 'text' : 'password'}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 pr-14 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            required
            minLength={8}
          />
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="absolute right-2 top-1/2 -translate-y-1/2 rounded px-2 py-1 text-xs text-gray-400 hover:bg-gray-700"
          >
            {showPassword ? 'Hide' : 'Show'}
          </button>
        </div>
        {newPassword && newPassword.length > 0 && (
          <div className="mt-2">
            <PasswordStrengthBar password={newPassword} />
          </div>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300">
          Confirm new password
        </label>
        <input
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
          required
        />
      </div>

      {error && (
        <div className="rounded-lg bg-red-900/50 px-3 py-2 text-sm text-red-300">
          {error}
        </div>
      )}
      {success && (
        <div className="rounded-lg bg-emerald-900/50 px-3 py-2 text-sm text-emerald-300">
          {success}
        </div>
      )}

      <button
        type="submit"
        disabled={submitting}
        className="rounded-lg bg-emerald-600 px-6 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
      >
        {submitting ? 'Changing...' : 'Change password'}
      </button>
    </form>
  )
}

function TwoFactorSection() {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(true)
  const [setupData, setSetupData] = useState<{ secret: string; qrCodeUrl: string; qrDataUrl: string } | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)

  const loadStatus = useCallback(async () => {
    setLoading(true)
    try {
      const res = await get2FAStatus()
      setEnabled(res.enabled)
    } catch {
      setError('Failed to load 2FA status')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadStatus()
  }, [loadStatus])

  const handleSetup = async () => {
    setError('')
    setBusy(true)
    try {
      const res = await setup2FA()
      const qrDataUrl = await QRCode.toDataURL(res.qrCodeUrl, {
        width: 200,
        margin: 2,
        color: { dark: '#34d399', light: '#111827' },
      })
      setSetupData({ ...res, qrDataUrl })
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to setup 2FA')
    } finally {
      setBusy(false)
    }
  }

  const handleEnable = async () => {
    if (!code || code.length !== 6) return
    setError('')
    setBusy(true)
    try {
      await enable2FA(code)
      setEnabled(true)
      setSetupData(null)
      setCode('')
      setMessage('Two-factor authentication enabled')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to enable 2FA')
    } finally {
      setBusy(false)
    }
  }

  const handleDisable = async () => {
    setError('')
    setBusy(true)
    try {
      await disable2FA()
      setEnabled(false)
      setMessage('Two-factor authentication disabled')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to disable 2FA')
    } finally {
      setBusy(false)
    }
  }

  if (loading) {
    return <LoadingSpinner />
  }

  return (
    <div className="space-y-4 max-w-md">
      {message && (
        <div className="rounded-lg bg-emerald-900/50 px-3 py-2 text-sm text-emerald-300">
          {message}
        </div>
      )}
      {error && (
        <div className="rounded-lg bg-red-900/50 px-3 py-2 text-sm text-red-300">
          {error}
        </div>
      )}

      {enabled === true && (
        <div>
          <div className="flex items-center gap-2 mb-4">
            <div className="h-2 w-2 rounded-full bg-emerald-500" />
            <span className="text-sm text-emerald-400">Two-factor authentication is enabled</span>
          </div>
          <button
            onClick={handleDisable}
            disabled={busy}
            className="rounded-lg bg-red-900/50 px-4 py-2 text-sm text-red-300 hover:bg-red-900/70 disabled:opacity-50"
          >
            {busy ? 'Disabling...' : 'Disable 2FA'}
          </button>
        </div>
      )}

      {enabled === false && !setupData && (
        <div>
          <p className="text-sm text-gray-400 mb-4">
            Add an extra layer of security by requiring a one-time code from your authenticator app.
          </p>
          <button
            onClick={handleSetup}
            disabled={busy}
            className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            {busy ? 'Setting up...' : 'Setup 2FA'}
          </button>
        </div>
      )}

      {setupData && (
        <div className="space-y-4">
          <p className="text-sm text-gray-400">
            Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
          </p>
          <img
            src={setupData.qrDataUrl}
            alt="2FA QR Code"
            className="rounded-lg"
          />
          <div>
            <p className="text-xs text-gray-500 mb-1">Or enter this secret manually:</p>
            <code className="block rounded bg-gray-800 px-3 py-2 text-sm font-mono text-gray-300 break-all">
              {setupData.secret}
            </code>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Verification code
            </label>
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="000000"
              maxLength={6}
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 font-mono tracking-widest text-center focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            />
          </div>
          <button
            onClick={handleEnable}
            disabled={busy || code.length !== 6}
            className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            {busy ? 'Verifying...' : 'Enable 2FA'}
          </button>
        </div>
      )}
    </div>
  )
}

function DevicesSection() {
  const [devices, setDevices] = useState<DeviceResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await getDevices()
      setDevices(res.devices)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load devices')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const handleDelete = async (id: string) => {
    if (!window.confirm('Remove this device?')) return
    try {
      await deleteDevice(id)
      setDevices((prev) => prev.filter((d) => d.id !== id))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to remove device')
    }
  }

  if (loading) {
    return <LoadingSpinner />
  }

  return (
    <div className="space-y-3 max-w-md">
      {error && (
        <div className="rounded-lg bg-red-900/50 px-3 py-2 text-sm text-red-300">
          {error}
        </div>
      )}
      {devices.length === 0 ? (
        <p className="text-sm text-gray-500">No devices registered</p>
      ) : (
        devices.map((device) => (
          <div
            key={device.id}
            className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-900/50 px-4 py-3"
          >
            <div>
              <p className="text-sm text-gray-200">{device.deviceName}</p>
              <p className="text-xs text-gray-500">
                Last accessed: {new Date(device.lastAccessedAt).toLocaleDateString()}
              </p>
            </div>
            <button
              onClick={() => handleDelete(device.id)}
              className="rounded px-2 py-1 text-xs text-red-400 hover:bg-gray-800"
            >
              Remove
            </button>
          </div>
        ))
      )}
    </div>
  )
}

function AuditSection() {
  const [entries, setEntries] = useState<AuditLogEntry[]>([])
  const [page, setPage] = useState(0)
  const [totalPages, setTotalPages] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async (p: number) => {
    setLoading(true)
    try {
      const res = await getAuditLogs(p, 20)
      setEntries(res.logs)
      setTotalPages(res.totalPages)
      setPage(p)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load audit logs')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(0)
  }, [load])

  const formatAction = (action: string) => {
    return action
      .replace(/_/g, ' ')
      .toLowerCase()
      .replace(/^\w/, (c) => c.toUpperCase())
  }

  if (loading && entries.length === 0) {
    return <LoadingSpinner />
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="rounded-lg bg-red-900/50 px-3 py-2 text-sm text-red-300">
          {error}
        </div>
      )}
      {entries.length === 0 ? (
        <p className="text-sm text-gray-500">No audit log entries</p>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-left text-xs text-gray-500">
                  <th className="pb-2 pr-4 font-medium">Action</th>
                  <th className="pb-2 pr-4 font-medium">IP Address</th>
                  <th className="pb-2 font-medium">Date</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr key={entry.id} className="border-b border-gray-800/50">
                    <td className="py-2 pr-4 text-gray-200">
                      {formatAction(entry.action)}
                    </td>
                    <td className="py-2 pr-4 text-gray-400 font-mono text-xs">
                      {entry.ipAddress}
                    </td>
                    <td className="py-2 text-gray-400 whitespace-nowrap">
                      {new Date(entry.createdAt).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between">
            <button
              onClick={() => load(page - 1)}
              disabled={page === 0}
              className="rounded-lg bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 disabled:opacity-50"
            >
              Previous
            </button>
            <span className="text-xs text-gray-500">
              Page {page + 1} of {totalPages}
            </span>
            <button
              onClick={() => load(page + 1)}
              disabled={page >= totalPages - 1}
              className="rounded-lg bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  )
}
