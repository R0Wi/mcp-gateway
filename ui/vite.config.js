import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  base: '/ui/',
  build: {
    outDir: process.env.VITE_OUT_DIR || '../src/mcp_gateway/static/ui',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/auth/api': 'http://localhost:8000',
      '/oauth': 'http://localhost:8000',
    },
  },
});
