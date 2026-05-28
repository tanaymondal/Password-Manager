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

const TABS: { value: Tab; label: string; icon: string }[] = [
  { value: 'security', label: 'Security', icon: 'security' },
  { value: '2fa', label: 'Two-Factor Auth', icon: '2fa' },
  { value: 'devices', label: 'Devices', icon: 'devices' },
  { value: 'audit', label: 'Audit Log', icon: 'audit' },
]

export function SettingsPage() {
  const [tab, setTab] = useState<Tab>('security')

  return (
    <div className="mx-auto max-w-3xl p-6">
      <h1 className="text-2xl font-bold tracking-tight mb-6">Settings</h1>

      <div className="flex gap-1 mb-8 border-b border-gray-800/50">
        {TABS.map((t) => (
          <button
            key={t.value}
            onClick={() => setTab(t.value)}
            className={`relative px-4 py-3 text-sm font-medium transition-colors ${
              tab === t.value
                ? 'text-emerald-400'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            {t.label}
            {tab === t.value && (
              <span className="absolute inset-x-0 bottom-0 h-0.5 bg-emerald-500 rounded-full" />
            )}
          </button>
        ))}
      </div>

      <div className="rounded-2xl border border-gray-800/50 bg-gray-900/60 backdrop-blur-xl p-6 shadow-xl shadow-black/20">
        {tab === 'security' && <SecuritySection />}
        {tab === '2fa' && <TwoFactorSection />}
        {tab === 'devices' && <DevicesSection />}
        {tab === 'audit' && <AuditSection />}
      </div>
    </div>
  )
}

function SecuritySection() {
  const { changeMasterPassword, crossTabLocked } = useVault()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [progress, setProgress] = useState(0)
  const [showCurrentPassword, setShowCurrentPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

  if (crossTabLocked) {
    return (
      <div>
        <h2 className="text-lg font-medium mb-1">Password changed elsewhere</h2>
        <p className="text-sm text-gray-400 mb-4">
          Your master password was changed in another session. You've been logged out of this session.
        </p>
        <button
          onClick={() => window.location.reload()}
          className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-600/20 transition-all duration-200 hover:bg-emerald-500"
        >
          Reload to re-login
        </button>
      </div>
    )
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setProgress(0)

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      return
    }
    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters')
      return
    }
    if (newPassword === currentPassword) {
      setError('New password must be different from current password')
      return
    }
    setSubmitting(true)
    try {
      await changeMasterPassword(currentPassword, newPassword, setProgress)
      setSuccess('Password changed successfully. Other devices have been logged out.')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setTimeout(() => setSuccess(''), 6000)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to change password')
    } finally {
      setSubmitting(false)
      setProgress(0)
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
    <div>
      <h2 className="text-lg font-medium mb-1">Change master password</h2>
      <p className="text-sm text-gray-500 mb-6">
        Update the password used to unlock your vault
      </p>

      <form onSubmit={handleSubmit} className="space-y-5 max-w-md">
        <div>
          <label className="block text-sm font-medium text-gray-300">
            Current password
          </label>
          <div className="relative mt-1.5">
            <input
              type={showCurrentPassword ? 'text' : 'password'}
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 pr-14 text-sm text-gray-100 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
              required
            />
            <button
              type="button"
              onClick={() => setShowCurrentPassword(!showCurrentPassword)}
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded-lg px-2 py-1 text-xs text-gray-400 transition-colors hover:bg-gray-800"
            >
              {showCurrentPassword ? 'Hide' : 'Show'}
            </button>
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className="block text-sm font-medium text-gray-300">
              New password
            </label>
            <button
              type="button"
              onClick={generate}
              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-400 transition-all hover:bg-emerald-500/20"
            >
              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456zM16.894 20.567L16.5 21.75l-.394-1.183a2.25 2.25 0 00-1.423-1.423L13.5 18.75l1.183-.394a2.25 2.25 0 001.423-1.423l.394-1.183.394 1.183a2.25 2.25 0 001.423 1.423l1.183.394-1.183.394a2.25 2.25 0 00-1.423 1.423z" />
              </svg>
              Generate
            </button>
          </div>
          <div className="relative mt-1.5">
            <input
              type={showNewPassword ? 'text' : 'password'}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 pr-14 text-sm text-gray-100 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
              required
              minLength={8}
            />
            <button
              type="button"
              onClick={() => setShowNewPassword(!showNewPassword)}
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded-lg px-2 py-1 text-xs text-gray-400 transition-colors hover:bg-gray-800"
            >
              {showNewPassword ? 'Hide' : 'Show'}
            </button>
          </div>
          {newPassword && newPassword.length > 0 && (
            <div className="mt-2.5">
              <PasswordStrengthBar password={newPassword} />
            </div>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300">
            Confirm new password
          </label>
          <div className="relative mt-1.5">
            <input
              type={showConfirmPassword ? 'text' : 'password'}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 pr-14 text-sm text-gray-100 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
              required
            />
            <button
              type="button"
              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded-lg px-2 py-1 text-xs text-gray-400 transition-colors hover:bg-gray-800"
            >
              {showConfirmPassword ? 'Hide' : 'Show'}
            </button>
          </div>
        </div>

        {error && (
          <div className="rounded-xl border border-red-900/30 bg-red-950/30 px-4 py-2.5 text-sm text-red-400">
            {error}
          </div>
        )}
        {success && (
          <div className="rounded-xl border border-emerald-900/30 bg-emerald-950/30 px-4 py-2.5 text-sm text-emerald-400">
            {success}
          </div>
        )}

        <div className={`space-y-2 ${submitting ? '' : 'hidden'}`}>
          <div className="h-1.5 w-full rounded-full bg-gray-700/50 overflow-hidden">
            <div
              className="h-full rounded-full bg-emerald-500 transition-all duration-500 ease-out"
              style={{ width: `${progress * 100}%` }}
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={submitting}
          className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-600/20 transition-all duration-200 hover:bg-emerald-500 hover:shadow-emerald-500/30 active:scale-[0.98] disabled:opacity-50 disabled:shadow-none"
        >
          {submitting ? 'Changing…' : 'Change password'}
        </button>
      </form>
    </div>
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
  const [disabling, setDisabling] = useState(false)

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
        color: { dark: '#34d399', light: '#030712' },
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
    if (!code || code.length !== 6) return
    setError('')
    setBusy(true)
    try {
      await disable2FA(code)
      setEnabled(false)
      setDisabling(false)
      setCode('')
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
    <div>
      <h2 className="text-lg font-medium mb-1">Two-factor authentication</h2>
      <p className="text-sm text-gray-500 mb-6">
        Add an extra layer of security to your account
      </p>

      {message && (
        <div className="mb-5 rounded-xl border border-emerald-900/30 bg-emerald-950/30 px-4 py-2.5 text-sm text-emerald-400">
          {message}
        </div>
      )}
      {error && (
        <div className="mb-5 rounded-xl border border-red-900/30 bg-red-950/30 px-4 py-2.5 text-sm text-red-400">
          {error}
        </div>
      )}

      <div className="max-w-md space-y-5">
        {enabled === true && (
          <div>
            <div className="mb-4 inline-flex items-center gap-2 rounded-xl border border-emerald-900/30 bg-emerald-950/30 px-4 py-2.5">
              <div className="h-2 w-2 rounded-full bg-emerald-500 shadow-sm shadow-emerald-500/50" />
              <span className="text-sm text-emerald-400">Two-factor authentication is enabled</span>
            </div>
            {!disabling ? (
              <button
                onClick={() => setDisabling(true)}
                disabled={busy}
                className="inline-flex items-center gap-2 rounded-xl bg-red-950/30 px-4 py-2.5 text-sm font-medium text-red-400 transition-all duration-200 hover:bg-red-950/50 disabled:opacity-50"
              >
                Disable 2FA
              </button>
            ) : (
              <div className="space-y-4">
                <p className="text-sm text-gray-400">Enter a verification code from your authenticator app to disable 2FA.</p>
                <input
                  type="text"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  maxLength={6}
                  className="block w-full max-w-[160px] rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 text-sm text-gray-100 font-mono tracking-widest text-center transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                />
                <div className="flex gap-3">
                  <button
                    onClick={handleDisable}
                    disabled={busy || code.length !== 6}
                    className="inline-flex items-center gap-2 rounded-xl bg-red-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg transition-all duration-200 hover:bg-red-500 disabled:opacity-50 disabled:shadow-none"
                  >
                    {busy ? 'Disabling...' : 'Confirm Disable'}
                  </button>
                  <button
                    onClick={() => { setDisabling(false); setCode(''); setError('') }}
                    disabled={busy}
                    className="inline-flex items-center gap-2 rounded-xl bg-gray-800 px-4 py-2.5 text-sm font-medium text-gray-300 transition-all duration-200 hover:bg-gray-700 disabled:opacity-50"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {enabled === false && !setupData && (
          <div>
            <p className="text-sm text-gray-400 mb-4">
              Require a one-time code from your authenticator app when signing in.
            </p>
            <button
              onClick={handleSetup}
              disabled={busy}
              className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-600/20 transition-all duration-200 hover:bg-emerald-500 hover:shadow-emerald-500/30 active:scale-[0.98] disabled:opacity-50 disabled:shadow-none"
            >
              {busy ? 'Setting up...' : 'Setup 2FA'}
            </button>
          </div>
        )}

        {setupData && (
          <div className="space-y-5">
            <p className="text-sm text-gray-400">
              Scan this QR code with your authenticator app
            </p>
            <div className="inline-block rounded-xl border border-gray-700/50 bg-gray-950/50 p-3">
              <img
                src={setupData.qrDataUrl}
                alt="2FA QR Code"
                className="rounded-lg"
              />
            </div>
            <div>
              <p className="text-xs text-gray-500 mb-1.5">Or enter this secret manually:</p>
              <code className="block rounded-xl bg-gray-950/50 px-3.5 py-2.5 text-sm font-mono text-gray-300 break-all border border-gray-700/50">
                {setupData.secret}
              </code>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">
                Verification code
              </label>
              <input
                type="text"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                maxLength={6}
                className="block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 text-sm text-gray-100 font-mono tracking-widest text-center transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>
            <button
              onClick={handleEnable}
              disabled={busy || code.length !== 6}
              className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-600/20 transition-all duration-200 hover:bg-emerald-500 hover:shadow-emerald-500/30 active:scale-[0.98] disabled:opacity-50 disabled:shadow-none"
            >
              {busy ? 'Verifying...' : 'Enable 2FA'}
            </button>
          </div>
        )}
      </div>
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
    <div>
      <h2 className="text-lg font-medium mb-1">Connected devices</h2>
      <p className="text-sm text-gray-500 mb-6">
        Devices that have accessed your vault
      </p>

      {error && (
        <div className="mb-5 rounded-xl border border-red-900/30 bg-red-950/30 px-4 py-2.5 text-sm text-red-400">
          {error}
        </div>
      )}
      {devices.length === 0 ? (
        <p className="text-sm text-gray-500">No devices registered</p>
      ) : (
        <div className="space-y-2 max-w-md">
          {devices.map((device) => (
            <div
              key={device.id}
              className="flex items-center justify-between rounded-xl border border-gray-700/50 bg-gray-950/50 px-4 py-3 transition-all hover:border-gray-600/50"
            >
              <div className="flex items-center gap-3 min-w-0">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gray-800/50">
                  <svg className="h-4 w-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 1.5H8.25A2.25 2.25 0 006 3.75v16.5a2.25 2.25 0 002.25 2.25h7.5A2.25 2.25 0 0018 20.25V3.75a2.25 2.25 0 00-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 18.75h3" />
                  </svg>
                </div>
                <div className="min-w-0">
                  <p className="text-sm text-gray-200 truncate">{device.deviceName}</p>
                  <p className="text-xs text-gray-500">
                    Last accessed: {new Date(device.lastAccessedAt).toLocaleDateString()}
                  </p>
                </div>
              </div>
              <button
                onClick={() => handleDelete(device.id)}
                className="shrink-0 rounded-lg px-2 py-1 text-xs text-red-400 transition-colors hover:bg-red-950/30"
              >
                Remove
              </button>
            </div>
          ))}
        </div>
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
    <div>
      <h2 className="text-lg font-medium mb-1">Audit log</h2>
      <p className="text-sm text-gray-500 mb-6">
        Track activity on your account
      </p>

      {error && (
        <div className="mb-5 rounded-xl border border-red-900/30 bg-red-950/30 px-4 py-2.5 text-sm text-red-400">
          {error}
        </div>
      )}
      {entries.length === 0 ? (
        <p className="text-sm text-gray-500">No audit log entries</p>
      ) : (
        <div className="space-y-4">
          <div className="overflow-x-auto rounded-xl border border-gray-700/50">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700/50 text-left text-xs text-gray-500">
                  <th className="px-4 py-3 font-medium">Action</th>
                  <th className="px-4 py-3 font-medium">IP Address</th>
                  <th className="px-4 py-3 font-medium">Date</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry, i) => (
                  <tr
                    key={entry.id}
                    className={`${
                      i < entries.length - 1 ? 'border-b border-gray-800/30' : ''
                    }`}
                  >
                    <td className="px-4 py-3 text-gray-200">
                      {formatAction(entry.action)}
                    </td>
                    <td className="px-4 py-3 text-gray-400 font-mono text-xs">
                      {entry.ipAddress}
                    </td>
                    <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
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
              className="inline-flex items-center gap-1.5 rounded-xl bg-gray-800 px-3.5 py-2 text-sm text-gray-300 transition-all duration-200 hover:bg-gray-700 disabled:opacity-50"
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" />
              </svg>
              Previous
            </button>
            <span className="text-xs text-gray-500">
              Page {page + 1} of {totalPages}
            </span>
            <button
              onClick={() => load(page + 1)}
              disabled={page >= totalPages - 1}
              className="inline-flex items-center gap-1.5 rounded-xl bg-gray-800 px-3.5 py-2 text-sm text-gray-300 transition-all duration-200 hover:bg-gray-700 disabled:opacity-50"
            >
              Next
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
              </svg>
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
