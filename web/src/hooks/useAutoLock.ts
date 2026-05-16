import { useEffect, useRef } from 'react'

export function useAutoLock(
  isEnabled: boolean,
  onLock: () => void,
  timeoutMinutes: number = 5,
) {
  const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined)
  const onLockRef = useRef(onLock)
  onLockRef.current = onLock

  useEffect(() => {
    if (!isEnabled) return

    const resetTimer = () => {
      if (timerRef.current) clearTimeout(timerRef.current)
      timerRef.current = setTimeout(() => {
        onLockRef.current()
      }, timeoutMinutes * 60 * 1000)
    }

    const events = ['mousedown', 'keydown', 'touchstart', 'scroll']
    events.forEach((event) => window.addEventListener(event, resetTimer))
    resetTimer()

    return () => {
      events.forEach((event) =>
        window.removeEventListener(event, resetTimer),
      )
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [isEnabled, timeoutMinutes])
}
