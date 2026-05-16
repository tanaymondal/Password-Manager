import { useState, useEffect } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useVault } from '../context/VaultContext'

export function UnlockPage() {
  const { consumeMasterPassword } = useAuth()
  const { unlock, isUnlocked, isLoading, error, clearError } = useVault()
  const [password, setPassword] = useState('')
  const [autoTried, setAutoTried] = useState(false)

  useEffect(() => {
    if (!autoTried && !isUnlocked && !isLoading) {
      const saved = consumeMasterPassword()
      if (saved) {
        setAutoTried(true)
        unlock(saved)
      } else {
        setAutoTried(true)
      }
    }
  }, [autoTried, isUnlocked, isLoading, unlock, consumeMasterPassword])

  if (isUnlocked) {
    return <Navigate to="/vault" replace />
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    clearError()
    await unlock(password)
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-bold">Unlock Vault</h1>
          <p className="mt-1 text-sm text-gray-400">
            Enter your master password to decrypt your vault
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
              placeholder="Master password"
              className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            />
          </div>

          {error && (
            <div className="rounded-lg bg-red-900/50 px-3 py-2 text-sm text-red-300">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading || !password}
            className="w-full rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isLoading ? 'Decrypting...' : 'Unlock'}
          </button>
        </form>
      </div>
    </div>
  )
}
