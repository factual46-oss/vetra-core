import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', '**/.next/**', 'coverage/**'] },
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
  {
    /**
     * AUD-17: a versao anterior proibia qualquer import de `../../infra`, o que
     * reprovava o HealthController -- um controller PODE depender de
     * infraestrutura. A fronteira que importa e outra: a camada de dominio nao
     * conhece infraestrutura. Aplicada onde ela existe.
     */
    files: ['apps/*/src/**/domain/**/*.ts', 'packages/domain/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['**/infra/**', 'pg', 'ioredis', '@nestjs/*'],
              message:
                'Camada de dominio nao conhece infraestrutura nem framework. Defina uma porta (interface) e injete a implementacao.',
            },
          ],
        },
      ],
    },
  },
  {
    files: ['**/*.spec.ts', 'tests/**/*.ts', 'tools/**/*.mjs'],
    rules: { '@typescript-eslint/no-explicit-any': 'off' },
  },
);
