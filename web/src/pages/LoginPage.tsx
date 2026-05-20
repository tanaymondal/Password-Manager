import { useState } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useAuth } from '../context/AuthContext'

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
})

const twoFactorSchema = z.object({
  code: z.string().length(6, 'Code must be 6 digits'),
})

type LoginFormData = z.infer<typeof loginSchema>
type TwoFactorFormData = z.infer<typeof twoFactorSchema>

export function LoginPage() {
  const { login, verifyTwoFactor, isAuthenticated } = useAuth()
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [twoFactorRequired, setTwoFactorRequired] = useState(false)
  const [pendingEmail, setPendingEmail] = useState('')

  const {
    register: registerLogin,
    handleSubmit: handleLoginSubmit,
    formState: { errors: loginErrors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  })

  const {
    register: registerTwoFactor,
    handleSubmit: handleTwoFactorSubmit,
    formState: { errors: twoFactorErrors },
  } = useForm<TwoFactorFormData>({
    resolver: zodResolver(twoFactorSchema),
  })

  if (isAuthenticated) {
    return <Navigate to="/vault" replace />
  }

  const onLoginSubmit = async (data: LoginFormData) => {
    setError('')
    setSubmitting(true)
    try {
      const res = await login(data.email, data.password)
      if (res.twoFactorRequired) {
        setTwoFactorRequired(true)
        setPendingEmail(data.email)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Login failed')
    } finally {
      setSubmitting(false)
    }
  }

  const onTwoFactorSubmit = async (data: TwoFactorFormData) => {
    setError('')
    setSubmitting(true)
    try {
      await verifyTwoFactor(pendingEmail, data.code)
    } catch (e) {
      setError(e instanceof Error ? e.message : '2FA verification failed')
    } finally {
      setSubmitting(false)
    }
  }

  if (twoFactorRequired) {
    return (
      <div className="relative flex min-h-screen items-center justify-center overflow-hidden px-4">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(5,150,105,0.08),transparent_50%)]" />
        <div className="w-full max-w-sm">
          <div className="mb-8 text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-500/10 shadow-lg shadow-emerald-500/5">
              <svg className="h-6 w-6 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h1 className="text-2xl font-bold tracking-tight">Two-Factor Authentication</h1>
            <p className="mt-1.5 text-sm text-gray-500">Enter the 6-digit code from your authenticator app</p>
          </div>

          <div className="rounded-2xl border border-gray-800/50 bg-gray-900/60 backdrop-blur-xl p-6 shadow-xl shadow-black/20">
            <form onSubmit={handleTwoFactorSubmit(onTwoFactorSubmit)} className="space-y-5">
              <div>
                <label htmlFor="code" className="block text-sm font-medium text-gray-300">
                  Authentication Code
                </label>
                <input
                  id="code"
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  autoComplete="one-time-code"
                  {...registerTwoFactor('code')}
                  className="mt-1.5 block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 text-center text-2xl font-mono tracking-widest text-gray-100 placeholder-gray-500 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                  placeholder="000000"
                />
                {twoFactorErrors.code && (
                  <p className="mt-1.5 text-xs text-red-400">{twoFactorErrors.code.message}</p>
                )}
              </div>

              {error && (
                <div className="rounded-xl border border-red-900/30 bg-red-950/30 px-4 py-2.5 text-sm text-red-400">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="w-full rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-600/20 transition-all duration-200 hover:bg-emerald-500 hover:shadow-emerald-500/30 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50 disabled:shadow-none"
              >
                {submitting ? 'Verifying...' : 'Verify'}
              </button>
            </form>
          </div>

          <p className="mt-6 text-center text-sm text-gray-500">
            <button
              onClick={() => {
                setTwoFactorRequired(false)
                setPendingEmail('')
                setError('')
              }}
              className="font-medium text-emerald-400 transition-colors hover:text-emerald-300"
            >
              Back to login
            </button>
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden px-4">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(5,150,105,0.08),transparent_50%)]" />
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-500/10 shadow-lg shadow-emerald-500/5">
            <svg className="h-6 w-6 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold tracking-tight">SecureVault</h1>
          <p className="mt-1.5 text-sm text-gray-500">Sign in to your vault</p>
        </div>

        <div className="rounded-2xl border border-gray-800/50 bg-gray-900/60 backdrop-blur-xl p-6 shadow-xl shadow-black/20">
          <form onSubmit={handleLoginSubmit(onLoginSubmit)} className="space-y-5">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-300">
                Email
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                {...registerLogin('email')}
                className="mt-1.5 block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-500 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                placeholder="you@example.com"
              />
              {loginErrors.email && (
                <p className="mt-1.5 text-xs text-red-400">{loginErrors.email.message}</p>
              )}
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-300">
                Password
              </label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                {...registerLogin('password')}
                className="mt-1.5 block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-500 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                placeholder="Enter your password"
              />
              {loginErrors.password && (
                <p className="mt-1.5 text-xs text-red-400">{loginErrors.password.message}</p>
              )}
            </div>

            {error && (
              <div className="rounded-xl border border-red-900/30 bg-red-950/30 px-4 py-2.5 text-sm text-red-400">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-600/20 transition-all duration-200 hover:bg-emerald-500 hover:shadow-emerald-500/30 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50 disabled:shadow-none"
            >
              {submitting ? 'Signing in...' : 'Sign in'}
            </button>
          </form>
        </div>

        <p className="mt-6 text-center text-sm text-gray-500">
          Don't have an account?{' '}
          <Link to="/register" className="font-medium text-emerald-400 transition-colors hover:text-emerald-300">
            Create one
          </Link>
        </p>
      </div>
    </div>
  )
}
