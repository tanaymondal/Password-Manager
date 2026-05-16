import { useEffect, useState, useMemo } from 'react'
import { Link, useNavigate, Navigate } from 'react-router-dom'
import { useVault } from '../context/VaultContext'
import { EmptyState } from '../components/EmptyState'
import { LoadingSpinner } from '../components/LoadingSpinner'

export function VaultPage() {
  const { isUnlocked, loadEntries, entries, decrypted, isLoadingEntries, entryError } = useVault()
  const navigate = useNavigate()
  const [search, setSearch] = useState('')

  useEffect(() => {
    if (isUnlocked) loadEntries()
  }, [isUnlocked, loadEntries])

  const filtered = useMemo(() => {
    if (!search) return entries
    const q = search.toLowerCase()
    return entries.filter((e) => {
      const d = decrypted[e.id]
      if (!d) return false
      return (
        d.name.toLowerCase().includes(q) ||
        d.username.toLowerCase().includes(q) ||
        d.url.toLowerCase().includes(q)
      )
    })
  }, [entries, decrypted, search])

  if (!isUnlocked) {
    return <Navigate to="/unlock" replace />
  }

  if (isLoadingEntries) {
    return <LoadingSpinner className="h-full" size="lg" />
  }

  return (
    <div className="mx-auto max-w-4xl p-6">
      <div className="mb-6 flex items-center gap-4">
        <div className="relative flex-1">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search passwords..."
            className="block w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 pl-10 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
          />
          <svg
            className="absolute left-3 top-2.5 h-4 w-4 text-gray-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
        </div>
        <Link
          to="/vault/new"
          className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500"
        >
          Add password
        </Link>
      </div>

      {entryError && (
        <div className="mb-4 rounded-lg bg-red-900/50 px-3 py-2 text-sm text-red-300">
          {entryError}
        </div>
      )}

      {entries.length === 0 ? (
        <EmptyState
          title="Your vault is empty"
          description="Add your first password to get started"
          action={
            <Link
              to="/vault/new"
              className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500"
            >
              Add password
            </Link>
          }
        />
      ) : filtered.length === 0 ? (
        <div className="py-16 text-center text-sm text-gray-500">
          No entries match your search
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((entry) => {
            const d = decrypted[entry.id]
            return (
              <button
                key={entry.id}
                onClick={() => navigate(`/vault/${entry.id}`)}
                className="w-full rounded-lg border border-gray-800 bg-gray-900/50 px-4 py-3 text-left hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-200">
                      {d?.name || 'Unknown'}
                    </p>
                    <p className="text-xs text-gray-500">
                      {d?.username || d?.url || ''}
                    </p>
                  </div>
                  <svg
                    className="h-4 w-4 text-gray-600"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 5l7 7-7 7"
                    />
                  </svg>
                </div>
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
