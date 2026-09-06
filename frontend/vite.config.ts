/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// The dev server runs inside a Linux container while the source lives on a
// Windows filesystem. Both settings below exist because of that boundary and
// should not be removed without testing hot reload on Windows.
const hmrClientPort = Number(process.env.VITE_HMR_CLIENT_PORT ?? 54173)
const usePolling = process.env.CHOKIDAR_USEPOLLING === 'true'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    // Fail loudly rather than silently drifting to another port, which would
    // break the published host mapping.
    strictPort: true,
    watch: {
      // Windows/WSL2 does not propagate inotify events across the bind mount.
      usePolling,
      interval: 300,
    },
    hmr: {
      // The browser connects on the published host port, not 5173.
      clientPort: hmrClientPort,
    },
  },
  build: {
    rollupOptions: {
      output: {
        // Split the heavy, rarely-changing dependencies out of the app chunk.
        // Recharts alone is roughly half the bundle; keeping it separate means
        // a change to application code does not invalidate it in the browser
        // cache, and the login screen no longer waits on charting code it will
        // never use.
        manualChunks: {
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-charts': ['recharts'],
          'vendor-query': ['@tanstack/react-query'],
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
})
