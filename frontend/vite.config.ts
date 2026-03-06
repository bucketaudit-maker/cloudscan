import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Local dev: proxy /api to backend. Default localhost:8000; override with VITE_PROXY_TARGET.
const proxyTarget = process.env.VITE_PROXY_TARGET || 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: proxyTarget,
        changeOrigin: true,
      },
    },
  },
})
