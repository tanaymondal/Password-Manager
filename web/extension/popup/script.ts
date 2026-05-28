interface EntryFields {
  name: string
  username: string
  password: string
  url: string
  notes: string
}

const $ = (id: string) => document.getElementById(id)!

const views = {
  login: $('view-login'),
  twofa: $('view-2fa'),
  unlock: $('view-unlock'),
  vault: $('view-vault'),
}

function showView(name: keyof typeof views) {
  Object.values(views).forEach(v => v.classList.add('hidden'))
  views[name].classList.remove('hidden')
}

function setError(id: string, msg: string) {
  $(id).textContent = msg
}

async function checkStatus() {
  try {
    const status = await chrome.runtime.sendMessage({ type: 'getStatus' })
    if (status.isAuthenticated && status.isUnlocked) {
      showView('vault')
      loadEntries('')
    } else if (status.isAuthenticated && !status.isUnlocked) {
      showView('unlock')
    } else {
      showView('login')
    }
  } catch {
    showView('login')
  }
}

async function loadEntries(query: string) {
  try {
    const res = await chrome.runtime.sendMessage({ type: 'searchEntries', query })
    const list = $('vault-list')
    const empty = $('vault-empty')
    list.innerHTML = ''

    if (!res.entries || res.entries.length === 0) {
      empty.classList.remove('hidden')
      return
    }

    empty.classList.add('hidden')

    for (const entry of res.entries) {
      const item = document.createElement('div')
      item.className = 'entry-item'

      const nameEl = document.createElement('div')
      nameEl.className = 'entry-name'
      nameEl.textContent = entry.fields.name

      const userEl = document.createElement('div')
      userEl.className = 'entry-username'
      userEl.textContent = entry.fields.username

      item.appendChild(nameEl)
      item.appendChild(userEl)

      item.addEventListener('click', async () => {
        await chrome.runtime.sendMessage({ type: 'copyToClipboard', text: entry.fields.password })
        const orig = nameEl.textContent
        nameEl.textContent = 'Copied!'
        setTimeout(() => { nameEl.textContent = orig }, 1500)
      })

      list.appendChild(item)
    }
  } catch {
    $('vault-error').textContent = 'Failed to load entries'
  }
}

$('login-btn').addEventListener('click', async () => {
  const email = ($('login-email') as HTMLInputElement).value.trim()
  const passwordInput = $('login-password') as HTMLInputElement
  const password = passwordInput.value
  passwordInput.value = ''
  setError('login-error', '')

  if (!email || !password) {
    setError('login-error', 'Please enter email and password')
    return
  }

  const btn = $('login-btn') as HTMLButtonElement
  btn.disabled = true
  btn.textContent = 'Signing in...'

  try {
    const res = await chrome.runtime.sendMessage({ type: 'login', email, password })
    if (res.success) {
      showView('vault')
      loadEntries('')
    } else if (res.error === '2fa_required' && res.challengeId) {
      pending2FA = { email, password, challengeId: res.challengeId }
      showView('twofa')
    } else {
      setError('login-error', res.error || 'Login failed')
    }
  } catch (err: any) {
    setError('login-error', err.message || 'Login failed')
  } finally {
    btn.disabled = false
    btn.textContent = 'Sign In'
  }
})

$('2fa-btn').addEventListener('click', async () => {
  const code = ($('2fa-code') as HTMLInputElement).value.trim()
  setError('2fa-error', '')

  if (!code || code.length < 6) {
    setError('2fa-error', 'Please enter a valid 6-digit code')
    return
  }

  const btn = $('2fa-btn') as HTMLButtonElement
  btn.disabled = true
  btn.textContent = 'Verifying...'

  try {
    if (!pending2FA) {
      setError('2fa-error', 'Session expired. Please login again.')
      return
    }
    const res = await chrome.runtime.sendMessage({
      type: 'verify2fa',
      email: pending2FA.email,
      password: pending2FA.password,
      challengeId: pending2FA.challengeId,
      code,
    })
    pending2FA = null
    if (res.success) {
      showView('vault')
      loadEntries('')
    } else {
      pending2FA = null
      setError('2fa-error', res.error || 'Verification failed')
    }
  } catch (err: any) {
    setError('2fa-error', err.message || 'Verification failed')
  } finally {
    btn.disabled = false
    btn.textContent = 'Verify'
  }
})

$('unlock-btn').addEventListener('click', async () => {
  const unlockInput = $('unlock-password') as HTMLInputElement
  const password = unlockInput.value
  unlockInput.value = ''
  setError('unlock-error', '')

  if (!password) {
    setError('unlock-error', 'Please enter your master password')
    return
  }

  const btn = $('unlock-btn') as HTMLButtonElement
  btn.disabled = true
  btn.textContent = 'Unlocking...'

  try {
    const res = await chrome.runtime.sendMessage({ type: 'unlock', password })
    if (res.success) {
      showView('vault')
      loadEntries('')
    } else {
      setError('unlock-error', res.error || 'Incorrect password')
    }
  } catch (err: any) {
    setError('unlock-error', err.message || 'Unlock failed')
  } finally {
    btn.disabled = false
    btn.textContent = 'Unlock'
  }
})

$('unlock-logout').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'logout' })
  showView('login')
})

$('vault-logout').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'logout' })
  showView('login')
})

let pending2FA: { email: string; password: string; challengeId: string } | null = null

let searchTimer: ReturnType<typeof setTimeout> | null = null
$('vault-search').addEventListener('input', () => {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(() => {
    const query = ($('vault-search') as HTMLInputElement).value
    loadEntries(query)
  }, 200)
})

document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const active = document.activeElement
    if (active === $('login-email') || active === $('login-password')) {
      $('login-btn').click()
    } else if (active === $('unlock-password')) {
      $('unlock-btn').click()
    } else if (active === $('2fa-code')) {
      $('2fa-btn').click()
    }
  }
})

checkStatus()
