export function calculateStrength(password: string): number {
  let score = 0

  if (password.length >= 8) score++
  if (password.length >= 12) score++
  if (password.length >= 16) score++
  if (/[a-z]/.test(password)) score++
  if (/[A-Z]/.test(password)) score++
  if (/\d/.test(password)) score++
  if (/[!@#$%^&*(),.?":{}|<>_\-]/.test(password)) score++
  if (password.length >= 6 && /^.{6,}$/.test(password) && !/(.)\1{2,}/.test(password)) score++
  if (/[a-z].*[A-Z]|[A-Z].*[a-z]/.test(password) && /\d/.test(password)) score++
  if (/[!@#$%^&*(),.?":{}|<>_\-]/.test(password) && /\d/.test(password) && /[a-zA-Z]/.test(password)) score++

  return Math.min(score, 10)
}

export function getStrengthLabel(score: number): string {
  if (score < 2) return 'Very weak'
  if (score < 4) return 'Weak'
  if (score < 6) return 'Fair'
  if (score < 8) return 'Strong'
  return 'Very strong'
}

export function getStrengthColor(score: number): string {
  if (score < 2) return 'bg-red-500'
  if (score < 4) return 'bg-orange-500'
  if (score < 6) return 'bg-yellow-500'
  if (score < 8) return 'bg-emerald-400'
  return 'bg-emerald-600'
}
