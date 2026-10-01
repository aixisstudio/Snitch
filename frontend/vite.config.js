/**
 * Snitch — Vite configuration.
 *
 * EN: In dev, the API and WebSocket are proxied to the Python backend on
 *     :8000 so the frontend code can use relative URLs. `base: './'` makes
 *     the production build work when served from file:// by Electron.
 * FR: En dev, l'API et le WebSocket sont proxifiés vers le backend Python sur
 *     :8000 pour que le frontend utilise des URL relatives. `base: './'` permet
 *     au build de production de fonctionner servi en file:// par Electron.
 */
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: './',
  // EN: Vitest reads this — plain Node environment is enough for our pure
  //     logic tests (privacy scoring).
  // FR: Vitest lit cette clé — l'environnement Node suffit pour nos tests de
  //     logique pure (score de confidentialité).
  test: { environment: 'node' },
  server: {
    port: 5173,
    proxy: {
      '/ws':       { target: 'ws://localhost:8000', ws: true },
      '/graph':    { target: 'http://localhost:8000' },
      '/devices':  { target: 'http://localhost:8000' },
      '/alerts':   { target: 'http://localhost:8000' },
      '/timeline': { target: 'http://localhost:8000' },
      '/capture':  { target: 'http://localhost:8000' },
      '/media':    { target: 'http://localhost:8000' },
    },
  },
})
