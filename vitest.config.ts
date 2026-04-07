import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/cli.ts', 'src/index.ts', 'src/types.ts'],
      thresholds: {
        lines: 95,
        branches: 90,
        functions: 100,
      },
    },
  },
});
