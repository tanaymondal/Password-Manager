let autofillDropdown: HTMLDivElement | null = null
let activeField: HTMLInputElement | null = null

function findUsernameField(passwordField: HTMLInputElement): HTMLInputElement | null {
  const form = passwordField.closest('form')
  if (!form) return null
  const inputs = form.querySelectorAll<HTMLInputElement>('input[type="text"], input[type="email"], input:not([type])')
  for (const input of inputs) {
    const name = input.name.toLowerCase()
    const id = input.id.toLowerCase()
    const placeholder = input.placeholder.toLowerCase()
    if (
      name.includes('user') || name.includes('email') || name.includes('login') ||
      id.includes('user') || id.includes('email') || id.includes('login') ||
      placeholder.includes('user') || placeholder.includes('email') || placeholder.includes('login')
    ) {
      return input
    }
  }
  const firstTextInput = form.querySelector<HTMLInputElement>('input[type="text"], input[type="email"]')
  if (firstTextInput) return firstTextInput
  const allInputs = form.querySelectorAll<HTMLInputElement>('input')
  for (let i = 0; i < allInputs.length; i++) {
    if (allInputs[i] === passwordField && i > 0) return allInputs[i - 1]
  }
  return null
}

function removeDropdown() {
  if (autofillDropdown) {
    autofillDropdown.remove()
    autofillDropdown = null
  }
}

function createDropdown(entries: { id: string; fields: { name: string; username: string; password: string } }[], input: HTMLInputElement) {
  removeDropdown()

  const rect = input.getBoundingClientRect()
  const dropdown = document.createElement('div')
  dropdown.style.cssText = `
    position: fixed; top: ${rect.bottom + window.scrollY + 2}px;
    left: ${rect.left + window.scrollX}px; min-width: ${Math.max(rect.width, 200)}px;
    max-width: 350px; background: white; border: 1px solid #ddd;
    border-radius: 8px; box-shadow: 0 4px 16px rgba(0,0,0,0.15);
    z-index: 2147483647; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px; overflow: hidden;
  `

  const header = document.createElement('div')
  header.textContent = 'SecureVault'
  header.style.cssText = `
    padding: 8px 12px; font-weight: 600; color: #4f46e5;
    border-bottom: 1px solid #eee; font-size: 12px; text-transform: uppercase;
    letter-spacing: 0.5px;
  `
  dropdown.appendChild(header)

  if (entries.length === 0) {
    const empty = document.createElement('div')
    empty.textContent = 'No matching entries'
    empty.style.cssText = 'padding: 12px; color: #888; text-align: center; font-size: 13px;'
    dropdown.appendChild(empty)
  } else {
    for (const entry of entries) {
      const item = document.createElement('div')
      item.style.cssText = `
        padding: 10px 12px; cursor: pointer; display: flex; flex-direction: column;
        gap: 2px; border-bottom: 1px solid #f0f0f0; transition: background 0.15s;
      `
      item.addEventListener('mouseenter', () => { item.style.background = '#f5f5ff' })
      item.addEventListener('mouseleave', () => { item.style.background = '' })

      const nameEl = document.createElement('div')
      nameEl.textContent = entry.fields.name
      nameEl.style.cssText = 'font-weight: 500; color: #222;'

      const subEl = document.createElement('div')
      subEl.textContent = entry.fields.username
      subEl.style.cssText = 'font-size: 12px; color: #666;'

      item.appendChild(nameEl)
      item.appendChild(subEl)

      item.addEventListener('click', async (e) => {
        e.stopPropagation()
        removeDropdown()
        await fillCredentials(entry.fields.username, entry.fields.password)
      })

      dropdown.appendChild(item)
    }
  }

  document.body.appendChild(dropdown)
  autofillDropdown = dropdown

  const closeHandler = (e: MouseEvent) => {
    if (!dropdown.contains(e.target as Node)) {
      removeDropdown()
      document.removeEventListener('click', closeHandler)
    }
  }
  setTimeout(() => document.addEventListener('click', closeHandler), 0)
}

async function fillCredentials(username: string, password: string) {
  const passwordField = activeField
  if (!passwordField) return

  const usernameField = findUsernameField(passwordField)
  if (usernameField) {
    usernameField.value = username
    usernameField.dispatchEvent(new Event('input', { bubbles: true }))
    usernameField.dispatchEvent(new Event('change', { bubbles: true }))
  }

  passwordField.value = password
  passwordField.dispatchEvent(new Event('input', { bubbles: true }))
  passwordField.dispatchEvent(new Event('change', { bubbles: true }))
}

async function handleFocus(event: FocusEvent) {
  const target = event.target as HTMLInputElement
  if (!target || target.type !== 'password') return

  activeField = target

  const url = window.location.href
  try {
    const response = await chrome.runtime.sendMessage({ type: 'getEntriesForUrl', url })
    if (response?.entries?.length > 0) {
      createDropdown(response.entries, target)
    }
  } catch {
    // background not available
  }
}

document.addEventListener('focusin', handleFocus)
