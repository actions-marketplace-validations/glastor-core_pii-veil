import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';

// https://astro.build/config
export default defineConfig({
  integrations: [tailwind()],
  vite: {
    build: {
      rollupOptions: {
        external: ['/wasm/pii_veil_wasm.js']
      }
    },
    server: {
      fs: {
        allow: ['..']
      }
    }
  }
});
