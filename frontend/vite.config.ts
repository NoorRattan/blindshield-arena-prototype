/// <reference types="vitest" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/v1': {
        target: process.env.VITE_BACKEND_URL || 'https://127.0.0.1:8443',
        changeOrigin: true,
        secure: false, // Accepts self-signed local CA in dev mode
        ws: false,
      },
    },
  },
});
