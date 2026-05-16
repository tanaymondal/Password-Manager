import { useState } from 'react'
import { Outlet, NavLink } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { ErrorBoundary } from './ErrorBoundary'

export function Layout() {
  const { logout, user } = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `block rounded-lg px-3 py-2 text-sm ${
      isActive
        ? 'bg-emerald-600/20 text-emerald-400'
        : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
    }`

  const sidebar = (
    <aside className="flex h-full w-56 flex-col border-r border-gray-800 bg-gray-950">
      <div className="flex h-14 items-center px-4 border-b border-gray-800">
        <h1 className="text-lg font-bold">SecureVault</h1>
      </div>

      <nav className="flex-1 space-y-1 p-3">
        <NavLink to="/vault" end className={linkClass} onClick={() => setSidebarOpen(false)}>
          Vault
        </NavLink>
        <NavLink to="/settings" className={linkClass} onClick={() => setSidebarOpen(false)}>
          Settings
        </NavLink>
      </nav>

      <div className="border-t border-gray-800 p-3 space-y-2">
        <div className="px-3 py-1 text-xs text-gray-500 truncate">
          {user?.email}
        </div>
        <button
          onClick={() => { logout(); setSidebarOpen(false) }}
          className="w-full rounded-lg px-3 py-2 text-left text-sm text-red-400 hover:bg-gray-800"
        >
          Sign out
        </button>
      </div>
    </aside>
  )

  return (
    <div className="flex h-screen">
      {/* Desktop sidebar */}
      <div className="hidden md:flex">{sidebar}</div>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div
            className="absolute inset-0 bg-black/50"
            onClick={() => setSidebarOpen(false)}
          />
          <div className="absolute inset-y-0 left-0">{sidebar}</div>
        </div>
      )}

      {/* Mobile header + main content */}
      <div className="flex flex-1 flex-col min-w-0">
        <div className="flex h-14 items-center gap-3 border-b border-gray-800 bg-gray-950 px-4 md:hidden">
          <button
            onClick={() => setSidebarOpen(true)}
            className="rounded-lg p-2 text-gray-400 hover:bg-gray-800"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          <h1 className="text-lg font-bold">SecureVault</h1>
        </div>

        <main className="flex-1 overflow-auto bg-gray-900">
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  )
}
