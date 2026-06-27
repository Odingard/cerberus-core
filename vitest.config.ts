import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: {
    alias: {
      '@cerberus-ai/core/internal': fileURLToPath(new URL('./src/internal.ts', import.meta.url)),
      '@cerberus-ai/core': fileURLToPath(new URL('./src/index.ts', import.meta.url)),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/adapters/**', 'src/**/index.ts', 'src/types/**'],
    },
  },
});
