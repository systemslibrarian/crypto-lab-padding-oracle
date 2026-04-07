import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-padding-oracle/',
  build: {
    outDir: 'dist',
    target: 'es2020',
  },
});
