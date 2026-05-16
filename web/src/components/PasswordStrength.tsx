import { calculateStrength, getStrengthLabel, getStrengthColor } from '../crypto/strength'

export function PasswordStrengthBar({ password }: { password: string }) {
  if (!password) return null

  const strength = calculateStrength(password)

  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 flex-1 rounded-full bg-gray-700 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${getStrengthColor(strength)}`}
          style={{ width: `${(strength / 10) * 100}%` }}
        />
      </div>
      <span className="text-xs text-gray-400">{getStrengthLabel(strength)}</span>
    </div>
  )
}
