import { useState, useCallback, useRef } from 'react'

export function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  const clearTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined)

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)

      if (clearTimerRef.current) clearTimeout(clearTimerRef.current)
      clearTimerRef.current = setTimeout(async () => {
        try {
          const current = await navigator.clipboard.readText()
          if (current === value) {
            await navigator.clipboard.writeText('')
          }
        } catch {
          // clipboard read not available — skip clear
        }
      }, 30000)
    } catch {
      // clipboard write not available
    }
  }, [value])

  return (
    <button
      type="button"
      onClick={copy}
      className="rounded px-2 py-1 text-xs text-gray-400 hover:bg-gray-700 hover:text-gray-200"
    >
      {copied ? 'Copied!' : 'Copy'}
    </button>
  )
}
