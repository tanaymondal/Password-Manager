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
          className="mb-4 text-sm text-gray-400 hover:text-gray-200"
        >
          ← Back
        </button>
        <h2 className="mb-6 text-lg font-medium">Edit entry</h2>
        <VaultEntryForm
          initial={fields}
          onSave={handleSave}
          onCancel={() => setIsEditing(false)}
          submitLabel="Save changes"
        />
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-2xl p-6">
      <button
        onClick={() => navigate('/vault')}
        className="mb-4 text-sm text-gray-400 hover:text-gray-200"
      >
        ← Back to vault
      </button>

      {entryError && (
        <div className="mb-4 rounded-lg bg-red-900/50 px-3 py-2 text-sm text-red-300">
          {entryError}
        </div>
      )}

      <div className="rounded-lg border border-gray-800 bg-gray-900/50">
        <div className="border-b border-gray-800 px-5 py-4">
          <h2 className="text-lg font-medium">{fields.name}</h2>
        </div>

        <div className="space-y-4 px-5 py-4">
          <FieldRow label="URL" value={fields.url} />
          <FieldRow label="Username" value={fields.username} />
          <FieldRow label="Password" value={fields.password} />
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">
              Notes
            </label>
            <p className="whitespace-pre-wrap text-sm text-gray-200">
              {fields.notes || '—'}
            </p>
          </div>
        </div>

        <div className="flex gap-3 border-t border-gray-800 px-5 py-3">
          <button
            onClick={() => {
              clearEntryError()
              setIsEditing(true)
            }}
            className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-300 hover:bg-gray-700"
          >
            Edit
          </button>
          <button
            onClick={handleDelete}
            disabled={deleting}
            className="rounded-lg bg-red-900/50 px-4 py-2 text-sm text-red-300 hover:bg-red-900/70 disabled:opacity-50"
          >
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
      <label className="block text-xs font-medium text-gray-500 mb-1">
        {label}
      </label>
      <div className="flex items-center gap-2">
        <span className="text-sm text-gray-200 font-mono">
          {value || '—'}
        </span>
        {value && <CopyButton value={value} />}
      </div>
    </div>
  )
}
