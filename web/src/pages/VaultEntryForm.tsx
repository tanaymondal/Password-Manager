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
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-300">Name</label>
        <input
          type="text"
          {...register('name')}
          className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
          placeholder="e.g. Google"
        />
        {errors.name && (
          <p className="mt-1 text-xs text-red-400">{errors.name.message}</p>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300">URL</label>
        <input
          type="text"
          {...register('url')}
          className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
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
          className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
          placeholder="user@gmail.com"
        />
      </div>

      <div>
        <div className="flex items-center justify-between">
          <label className="block text-sm font-medium text-gray-300">
            Password
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
            autoComplete="off"
            {...register('password')}
            className="block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 pr-16 text-sm text-gray-100 font-mono placeholder-gray-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            placeholder="Enter or generate a password"
          />
          <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
            {password && <CopyButton value={password} />}
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="rounded px-2 py-1 text-xs text-gray-400 hover:bg-gray-700 hover:text-gray-200"
            >
              {showPassword ? 'Hide' : 'Show'}
            </button>
          </div>
        </div>
        {password && password.length > 0 && (
          <div className="mt-2">
            <PasswordStrengthBar password={password} />
          </div>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300">Notes</label>
        <textarea
          rows={3}
          {...register('notes')}
          className="mt-1 block w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 resize-none"
          placeholder="Optional notes..."
        />
      </div>

      {entryError && (
        <div className="rounded-lg bg-red-900/50 px-3 py-2 text-sm text-red-300">
          {entryError}
        </div>
      )}

      <div className="flex gap-3">
        <button
          type="submit"
          disabled={submitting}
          className="rounded-lg bg-emerald-600 px-6 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting ? 'Saving...' : submitLabel}
        </button>
        <button
          type="button"
          onClick={onCancel ? onCancel : () => navigate('/vault')}
          className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-300 hover:bg-gray-700"
        >
          Cancel
        </button>
      </div>
    </form>
  )
}
