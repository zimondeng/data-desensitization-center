import { mergeConfig, defineConfig } from 'vitest/config'
import viteConfig from './vite.config'

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: 'happy-dom',
      globals: false,
      setupFiles: ['./src/test-setup.ts'],
      include: ['src/**/__tests__/*.spec.ts'],
      server: {
        deps: {
          inline: ['element-plus'],
        },
      },
    },
  }),
)
