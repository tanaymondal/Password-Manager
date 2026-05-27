import { useEffect, useState, useMemo, useRef } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useVault } from '../context/VaultContext'
import { consumeAutoUnlockVaultKey } from '../context/AuthContext'
import { EmptyState } from '../components/EmptyState'
import { LoadingSpinner } from '../components/LoadingSpinner'

export function VaultPage() {
  const { isUnlocked, unlock, loadEntries, entries, decrypted, isLoadingEntries, entryError } = useVault()
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [unlockPw, setUnlockPw] = useState('')
  const [unlockErr, setUnlockErr] = useState('')
  const autoUnlocked = useRef(false)

  useEffect(() => {
    if (!isUnlocked && !autoUnlocked.current) {
      const preDerivedKey = consumeAutoUnlockVaultKey()
      if (preDerivedKey) {
        autoUnlocked.current = true
        unlock('', preDerivedKey).catch(() => {})
      }
    }
  }, [isUnlocked, unlock])

  useEffect(() => {
    if (isUnlocked) loadEntries()
  }, [isUnlocked, loadEntries])

  const filtered = useMemo(() => {
    let result = [...entries]
    if (search) {
      const q = search.toLowerCase()
      result = result.filter((e) => {
        const d = decrypted[e.id]
        if (!d) return false
        return (
          d.name.toLowerCase().includes(q) ||
          d.username.toLowerCase().includes(q) ||
          d.url.toLowerCase().includes(q)
        )
      })
    }
    result.sort((a, b) => {
      const na = (decrypted[a.id]?.name || '').toLowerCase()
      const nb = (decrypted[b.id]?.name || '').toLowerCase()
      return na.localeCompare(nb)
    })
    return result
  }, [entries, decrypted, search])

  if (!isUnlocked) {
    return (
      <div className="relative flex min-h-full items-center justify-center px-4">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(5,150,105,0.08),transparent_50%)]" />
        <div className="w-full max-w-sm">
          <div className="mb-8 text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-500/10 shadow-lg shadow-emerald-500/5">
              <svg className="h-6 w-6 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h1 className="text-2xl font-bold tracking-tight">Unlock Vault</h1>
            <p className="mt-1.5 text-sm text-gray-500">Enter your master password</p>
          </div>

          <div className="rounded-2xl border border-gray-800/50 bg-gray-900/60 backdrop-blur-xl p-6 shadow-xl shadow-black/20">
            <form onSubmit={async (e) => { e.preventDefault(); setUnlockErr(''); try { await unlock(unlockPw) } catch { setUnlockErr('Wrong password') } }} className="space-y-5">
              <input
                type="password"
                value={unlockPw}
                onChange={(e) => setUnlockPw(e.target.value)}
                autoFocus
                placeholder="Master password"
                className="block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-500 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
              />
              {unlockErr && (
                <div className="rounded-xl border border-red-900/30 bg-red-950/30 px-4 py-2.5 text-sm text-red-400">{unlockErr}</div>
              )}
              <button
                type="submit"
                className="w-full rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-600/20 transition-all duration-200 hover:bg-emerald-500 hover:shadow-emerald-500/30 active:scale-[0.98]"
              >
                Unlock
              </button>
            </form>
          </div>
        </div>
      </div>
    )
  }

  if (isLoadingEntries) {
    return <LoadingSpinner className="h-full" size="lg" />
  }

  return (
    <div className="mx-auto max-w-4xl p-6">
      <div className="mb-6 flex items-center gap-4">
        <div className="relative flex-1">
          <svg
            className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
          </svg>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search passwords..."
            className="block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 pl-10 pr-4 py-2.5 text-sm text-gray-100 placeholder-gray-500 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
          />
        </div>
        <Link
          to="/vault/new"
          className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-600/20 transition-all duration-200 hover:bg-emerald-500 hover:shadow-emerald-500/30 active:scale-[0.98]"
        >
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
          </svg>
          Add password
        </Link>
      </div>

      {entryError && (
        <div className="mb-4 rounded-xl border border-red-900/30 bg-red-950/30 px-4 py-2.5 text-sm text-red-400">
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
              className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-600/20 transition-all duration-200 hover:bg-emerald-500 hover:shadow-emerald-500/30 active:scale-[0.98]"
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
              </svg>
              Add password
            </Link>
          }
        />
      ) : filtered.length === 0 ? (
        <div className="py-20 text-center">
          <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-gray-800/50">
            <svg className="h-6 w-6 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
            </svg>
          </div>
          <p className="text-sm text-gray-500">No entries match your search</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((entry) => {
            const d = decrypted[entry.id]
            return (
              <button
                key={entry.id}
                onClick={() => navigate(`/vault/${entry.id}`)}
                className="group w-full rounded-xl border border-gray-800/50 bg-gray-900/40 px-5 py-3.5 text-left backdrop-blur-sm transition-all duration-200 hover:border-gray-700/50 hover:bg-gray-900/60 hover:shadow-lg hover:shadow-black/10"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-emerald-500/10">
                      <svg className="h-4.5 w-4.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
                      </svg>
                    </div>
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-gray-200 group-hover:text-gray-100 transition-colors">
                        {d?.name || 'Unknown'}
                      </p>
                      <p className="truncate text-xs text-gray-500">
                        {d?.username || d?.url || ''}
                      </p>
                    </div>
                  </div>
                  <svg
                    className="h-4 w-4 shrink-0 text-gray-600 transition-colors group-hover:text-gray-400"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={2}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
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
