import { defineConfig } from 'vite'
import { resolve } from 'path'

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        background: resolve(__dirname, 'src/background.ts'),
        content: resolve(__dirname, 'src/content.ts'),
        popup: resolve(__dirname, 'popup/index.html'),
      },
      output: {
        entryFileNames: chunk => {
          if (chunk.name === 'background' || chunk.name === 'content') {
            return '[name].js'
          }
          return 'popup/[name].[hash].js'
        },
        chunkFileNames: 'chunks/[name].[hash].js',
        assetFileNames: asset => {
          if (asset.name?.endsWith('.css')) return 'popup/style.[hash].css'
          return 'assets/[name].[hash][extname]'
        },
      },
    },
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
})
