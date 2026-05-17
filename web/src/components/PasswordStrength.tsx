import { calculateStrength, getStrengthLabel, getStrengthColor } from '../crypto/strength'

export function PasswordStrengthBar({ password }: { password: string }) {
  if (!password) return null

  const strength = calculateStrength(password)
  const pct = (strength / 10) * 100

  return (
    <div className="flex items-center gap-3">
      <div className="h-1.5 flex-1 rounded-full bg-gray-700/50 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ease-out ${getStrengthColor(strength)}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs text-gray-500 min-w-[4rem] text-right">{getStrengthLabel(strength)}</span>
    </div>
  )
}
