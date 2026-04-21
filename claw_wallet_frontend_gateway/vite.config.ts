import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: '../sandbox/gateway_ui',
    emptyOutDir: true,
  },
  server: {
    host: '127.0.0.1',
    port: 4382,
    strictPort: true
  }
})
