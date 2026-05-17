import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useNavigate } from 'react-router-dom'
import { useVault, type EntryFields } from '../context/VaultContext'
import { generatePassword } from '../crypto/generator'
import { CopyButton } from '../components/CopyButton'
import { PasswordStrengthBar } from '../components/PasswordStrength'

const schema = z.object({
  name: z.string().min(1, 'Name is required'),
  url: z.string(),
  username: z.string(),
  password: z.string(),
  notes: z.string(),
})

type FormData = z.infer<typeof schema>

export function VaultEntryForm({
  initial,
  onSave,
  onCancel,
  submitLabel = 'Save',
}: {
  initial?: EntryFields
  onSave?: (data: EntryFields) => Promise<void>
  onCancel?: () => void
  submitLabel?: string
}) {
  const navigate = useNavigate()
  const { createEntry, entryError, clearEntryError } = useVault()
  const [submitting, setSubmitting] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    formState: { errors },
  } = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: initial || {
      name: '',
      url: '',
      username: '',
      password: '',
      notes: '',
    },
  })

  const password = watch('password')

  const generate = () => {
    const pw = generatePassword({
      length: 24,
      includeUppercase: true,
      includeLowercase: true,
      includeNumbers: true,
      includeSymbols: true,
      excludeAmbiguous: true,
    })
    setValue('password', pw, { shouldValidate: true })
  }

  const onSubmit = async (data: FormData) => {
    clearEntryError()
    setSubmitting(true)
    try {
      if (onSave) {
        await onSave(data)
      } else {
        await createEntry(data)
        navigate('/vault')
      }
    } catch {
      // error is set in context
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
      <div className="grid gap-5 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <label className="block text-sm font-medium text-gray-300">Name</label>
          <input
            type="text"
            {...register('name')}
            className="mt-1.5 block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-500 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
            placeholder="e.g. Google"
          />
          {errors.name && (
            <p className="mt-1.5 text-xs text-red-400">{errors.name.message}</p>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300">URL</label>
          <input
            type="text"
            {...register('url')}
            className="mt-1.5 block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-500 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
            placeholder="https://accounts.google.com"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300">
            Username
          </label>
          <input
            type="text"
            autoComplete="off"
            {...register('username')}
            className="mt-1.5 block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-500 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
            placeholder="user@gmail.com"
          />
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label className="block text-sm font-medium text-gray-300">
            Password
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
            type={showPassword ? 'text' : 'password'}
            autoComplete="off"
            {...register('password')}
            className="block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 pr-20 text-sm text-gray-100 font-mono placeholder-gray-500 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
            placeholder="Enter or generate a password"
          />
          <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
            {password && <CopyButton value={password} />}
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="rounded-lg px-2 py-1 text-xs text-gray-400 transition-colors hover:bg-gray-800 hover:text-gray-200"
            >
              {showPassword ? 'Hide' : 'Show'}
            </button>
          </div>
        </div>
        {password && password.length > 0 && (
          <div className="mt-2.5">
            <PasswordStrengthBar password={password} />
          </div>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300">Notes</label>
        <textarea
          rows={3}
          {...register('notes')}
          className="mt-1.5 block w-full rounded-xl border border-gray-700/50 bg-gray-950/50 px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-500 transition-all duration-200 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 resize-none"
          placeholder="Optional notes..."
        />
      </div>

      {entryError && (
        <div className="rounded-xl border border-red-900/30 bg-red-950/30 px-4 py-2.5 text-sm text-red-400">
          {entryError}
        </div>
      )}

      <div className="flex gap-3 pt-2">
        <button
          type="submit"
          disabled={submitting}
          className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-600/20 transition-all duration-200 hover:bg-emerald-500 hover:shadow-emerald-500/30 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50 disabled:shadow-none"
        >
          {submitting ? 'Saving...' : submitLabel}
        </button>
        <button
          type="button"
          onClick={onCancel ? onCancel : () => navigate('/vault')}
          className="rounded-xl bg-gray-800 px-4 py-2.5 text-sm font-medium text-gray-300 transition-all duration-200 hover:bg-gray-700 hover:text-gray-100"
        >
          Cancel
        </button>
      </div>
    </form>
  )
}
