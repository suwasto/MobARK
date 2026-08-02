import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// M0 scaffold. Tailwind + design tokens from the mockup arrive in M5.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Same-origin dev proxy: avoids CORS and matches how the built app
      // will be served from FastAPI in production.
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
