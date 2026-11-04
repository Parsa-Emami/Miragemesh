import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';

export default defineConfig(({ mode }) => ({
  root: fileURLToPath(new URL('.', import.meta.url)),
  base: mode === 'pages' ? '/Miragemesh/' : '/',
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
  build: {
    outDir: fileURLToPath(new URL(mode === 'pages' ? '../../dist/pages' : '../../dist/web', import.meta.url)),
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
  },
}));
