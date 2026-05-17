import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useVault, type EntryFields } from '../context/VaultContext'
import { CopyButton } from '../components/CopyButton'
import { VaultEntryForm } from './VaultEntryForm'

export function VaultEntryPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { decrypted, entries, updateEntry, deleteEntry, entryError, clearEntryError } = useVault()
  const [isEditing, setIsEditing] = useState(false)
  const [deleting, setDeleting] = useState(false)

  const entry = entries.find((e) => e.id === id)
  const fields = id ? decrypted[id] : undefined

  if (!entry || !fields) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        Entry not found
      </div>
    )
  }

  const handleSave = async (data: EntryFields) => {
    if (!id) return
    await updateEntry(id, data)
    setIsEditing(false)
  }

  const handleDelete = async () => {
    if (!id) return
    if (!window.confirm('Delete this password permanently?')) return
    setDeleting(true)
    try {
      await deleteEntry(id)
      navigate('/vault', { replace: true })
    } finally {
      setDeleting(false)
    }
  }

  if (isEditing) {
    return (
      <div className="mx-auto max-w-2xl p-6">
        <button
          onClick={() => setIsEditing(false)}
          className="group mb-6 inline-flex items-center gap-1.5 text-sm text-gray-500 transition-colors hover:text-gray-300"
        >
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" />
          </svg>
          Back
        </button>

        <div className="rounded-2xl border border-gray-800/50 bg-gray-900/60 backdrop-blur-xl p-6 shadow-xl shadow-black/20">
          <h2 className="mb-6 text-lg font-medium">Edit entry</h2>
          <VaultEntryForm
            initial={fields}
            onSave={handleSave}
            onCancel={() => setIsEditing(false)}
            submitLabel="Save changes"
          />
        </div>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-2xl p-6">
      <button
        onClick={() => navigate('/vault')}
        className="group mb-6 inline-flex items-center gap-1.5 text-sm text-gray-500 transition-colors hover:text-gray-300"
      >
        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" />
        </svg>
        Back to vault
      </button>

      {entryError && (
        <div className="mb-4 rounded-xl border border-red-900/30 bg-red-950/30 px-4 py-2.5 text-sm text-red-400">
          {entryError}
        </div>
      )}

      <div className="rounded-2xl border border-gray-800/50 bg-gray-900/60 backdrop-blur-xl shadow-xl shadow-black/20">
        <div className="flex items-center gap-3 border-b border-gray-800/50 px-6 py-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/10">
            <svg className="h-5 w-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
            </svg>
          </div>
          <h2 className="text-lg font-medium">{fields.name}</h2>
        </div>

        <div className="space-y-5 px-6 py-5">
          <FieldRow label="URL" value={fields.url} />
          <FieldRow label="Username" value={fields.username} />
          <FieldRow label="Password" value={fields.password} />
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1.5">
              Notes
            </label>
            <p className="whitespace-pre-wrap rounded-xl bg-gray-950/50 px-3.5 py-2.5 text-sm text-gray-200">
              {fields.notes || <span className="text-gray-500 italic">No notes</span>}
            </p>
          </div>
        </div>

        <div className="flex gap-3 border-t border-gray-800/50 px-6 py-4">
          <button
            onClick={() => {
              clearEntryError()
              setIsEditing(true)
            }}
            className="inline-flex items-center gap-2 rounded-xl bg-gray-800 px-4 py-2.5 text-sm font-medium text-gray-300 transition-all duration-200 hover:bg-gray-700 hover:text-gray-100"
          >
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
            </svg>
            Edit
          </button>
          <button
            onClick={handleDelete}
            disabled={deleting}
            className="inline-flex items-center gap-2 rounded-xl bg-red-950/30 px-4 py-2.5 text-sm font-medium text-red-400 transition-all duration-200 hover:bg-red-950/50 disabled:opacity-50"
          >
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
            </svg>
            {deleting ? 'Deleting...' : 'Delete'}
          </button>
        </div>
      </div>
    </div>
  )
}

function FieldRow({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div>
      <label className="block text-xs font-medium text-gray-500 mb-1.5">
        {label}
      </label>
      <div className="flex items-center gap-2 rounded-xl bg-gray-950/50 px-3.5 py-2.5">
        <span className="flex-1 text-sm text-gray-200 font-mono truncate">
          {value || <span className="text-gray-500 italic not-italic">—</span>}
        </span>
        {value && <CopyButton value={value} />}
      </div>
    </div>
  )
}
