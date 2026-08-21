import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    /**
     * AUD-16: os fontes usam especificadores com extensao `.js` (exigencia do
     * NodeNext), mas em disco os arquivos sao `.ts`. O Vite nao faz esse
     * mapeamento sozinho e TODAS as suites falhariam na resolucao de import.
     * Este alias reescreve apenas caminhos relativos.
     */
    alias: [{ find: /^(\.{1,2}\/.*)\.js$/, replacement: '$1' }],
  },
  test: {
    include: ['apps/**/*.spec.ts', 'packages/**/*.spec.ts', 'tests/**/*.spec.ts'],
    // Preenche o ambiente antes de qualquer import de servico (getEnv e memoizado).
    setupFiles: ['tests/setup-env.ts'],
    environment: 'node',
    hookTimeout: 30_000,
    testTimeout: 30_000,
    coverage: { provider: 'v8', reporter: ['text', 'lcov'] },
  },
});
