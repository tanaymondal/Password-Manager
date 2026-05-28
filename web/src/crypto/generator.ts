interface PasswordOptions {
  length: number
  includeUppercase: boolean
  includeLowercase: boolean
  includeNumbers: boolean
  includeSymbols: boolean
  excludeAmbiguous: boolean
}

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
const NUMBERS = '0123456789'
const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?'
const AMBIGUOUS = '0OIl1'

function getRandomChar(charset: string): string {
  const max = charset.length
  const array = new Uint32Array(1)
  // Rejection sampling to eliminate modulo bias
  const maxValid = 0xffffffff - (0xffffffff % max)
  do {
    crypto.getRandomValues(array)
  } while (array[0] >= maxValid)
  return charset[array[0] % max]
}

export function generatePassword(options: PasswordOptions): string {
  let charset = ''
  if (options.includeLowercase) charset += LOWERCASE
  if (options.includeUppercase) charset += UPPERCASE
  if (options.includeNumbers) charset += NUMBERS
  if (options.includeSymbols) charset += SYMBOLS

  if (options.excludeAmbiguous) {
    for (const char of AMBIGUOUS) {
      charset = charset.replace(char, '')
    }
  }

  if (!charset) charset = LOWERCASE

  const password = new Array(options.length)
    .fill(null)
    .map(() => getRandomChar(charset))

  return password.join('')
}
