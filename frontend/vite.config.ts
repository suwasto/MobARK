import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// M5 Phase B: Tailwind v4 (CSS-first @theme in src/index.css) + React.
// The dev proxy keeps the app same-origin with the FastAPI backend, matching
// how the built app is served from FastAPI in production.
// API_PROXY_TARGET lets a scratch backend (e.g. an empty-DB instance for
// verifying the first-run empty state) stand in during development.
const apiTarget = process.env.API_PROXY_TARGET ?? 'http://localhost:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      // Same-origin dev proxy: avoids CORS and matches how the built app
      // will be served from FastAPI in production.
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
})
