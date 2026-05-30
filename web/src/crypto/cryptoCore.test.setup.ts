import { beforeAll } from 'vitest'
import fs from 'fs'
import path from 'path'
import { initSync } from './wasm/securevault_crypto_core.js'

beforeAll(async () => {
  const wasmPath = path.resolve(__dirname, 'wasm/securevault_crypto_core_bg.wasm')
  const wasmBytes = fs.readFileSync(wasmPath)
  const module = new WebAssembly.Module(wasmBytes)
  initSync({ module })
})
