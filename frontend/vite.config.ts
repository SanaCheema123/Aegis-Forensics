import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { port: 5173, strictPort: true, proxy: { '/api': { target: process.env.AEGIS_API_PROXY || 'http://127.0.0.1:8000', changeOrigin: true } } },
  build: { rollupOptions: { output: { manualChunks: { charts: ['recharts'], ui: ['react', 'react-dom', '@radix-ui/react-dialog', '@radix-ui/react-tabs'] } } } },
  test: { environment: 'jsdom', setupFiles: ['./src/test-setup.ts'], include: ['src/**/*.test.{ts,tsx}'] },
})
