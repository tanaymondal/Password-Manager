import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    setupFiles: ['src/crypto/cryptoCore.test.setup.ts'],
    coverage: {
      include: ['src/crypto/cryptoCore.ts'],
      exclude: ['src/crypto/wasm/**'],
    },
  },
})
