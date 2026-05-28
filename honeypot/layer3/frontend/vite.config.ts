import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '0.0.0.0',  // glows.ai port forwarding 需要綁定所有介面
    proxy: {
      '/api': 'http://localhost:8001',
      '/ws': { target: 'ws://localhost:8001', ws: true }
    }
  }
})
