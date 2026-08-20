import { describe, expect, it } from 'vitest';
import { loadEnv, trustProxySetting } from './env.js';
import { REDACTED_PATHS } from '../infra/logging/logger.options.js';

const KEY_A = Buffer.alloc(32, 1).toString('base64');
const KEY_B = Buffer.alloc(32, 2).toString('base64');
const KEY_C = Buffer.alloc(32, 3).toString('base64');
const KEY_D = Buffer.alloc(32, 4).toString('base64');

const baseEnv = {
  DATABASE_URL: 'postgres://vlos_app:x@localhost:5432/vlos',
  // Fase 1A: pool separado do modulo de autenticacao (Alternativa B).
  DATABASE_AUTH_URL: 'postgres://vlos_auth:x@localhost:5432/vlos',
  REDIS_URL: 'redis://localhost:6379',
};

const prodEnv = {
  ...baseEnv,
  NODE_ENV: 'production',
  APP_KEK_BASE64: KEY_A,
  IDENTIFIER_PEPPER_BASE64: KEY_B,
  AUDIT_IP_HASH_KEY_BASE64: KEY_C,
  AUTH_PEPPER_BASE64: KEY_D,
  CORS_ORIGINS: 'https://app.vetra.com.br',
};

describe('validacao de ambiente', () => {
  it('aceita configuracao minima em desenvolvimento', () => {
    const env = loadEnv({ ...baseEnv } as NodeJS.ProcessEnv);
    expect(env.NODE_ENV).toBe('development');
    expect(env.API_PORT).toBe(3000);
  });

  it('recusa producao sem chaves de criptografia', () => {
    expect(() => loadEnv({ ...baseEnv, NODE_ENV: 'production' } as NodeJS.ProcessEnv)).toThrowError(
      /APP_KEK_BASE64/,
    );
  });

  it('recusa pepper igual a KEK', () => {
    expect(() =>
      loadEnv({ ...prodEnv, IDENTIFIER_PEPPER_BASE64: KEY_A } as NodeJS.ProcessEnv),
    ).toThrowError(/diferente da KEK/);
  });

  it('recusa chave que nao tem 32 bytes', () => {
    expect(() =>
      loadEnv({ ...prodEnv, APP_KEK_BASE64: Buffer.alloc(16).toString('base64') } as NodeJS.ProcessEnv),
    ).toThrowError(/32 bytes/);
  });

  it('recusa producao sem origens de CORS', () => {
    expect(() => loadEnv({ ...prodEnv, CORS_ORIGINS: '' } as NodeJS.ProcessEnv)).toThrowError(
      /CORS_ORIGINS/,
    );
  });

  it('aceita producao completa', () => {
    expect(loadEnv(prodEnv as NodeJS.ProcessEnv).NODE_ENV).toBe('production');
  });
});

describe('protecao contra conexao com a role de migracao', () => {
  it('recusa DATABASE_URL apontando para vlos_migrator', () => {
    expect(() =>
      loadEnv({
        ...baseEnv,
        DATABASE_URL: 'postgres://vlos_migrator:x@localhost:5432/vlos',
      } as NodeJS.ProcessEnv),
    ).toThrowError(/vlos_migrator/);
  });

  it('aceita vlos_app', () => {
    expect(loadEnv(baseEnv as NodeJS.ProcessEnv).DATABASE_URL).toContain('vlos_app');
  });
});

describe('confianca em proxy', () => {
  it('nao confia em nenhum proxy por padrao', () => {
    expect(trustProxySetting(loadEnv(baseEnv as NodeJS.ProcessEnv))).toBe(false);
  });

  it('confia apenas nos proxies declarados', () => {
    const env = loadEnv({ ...baseEnv, TRUSTED_PROXIES: '10.0.0.0/8, 172.18.0.1' } as NodeJS.ProcessEnv);
    expect(trustProxySetting(env)).toEqual(['10.0.0.0/8', '172.18.0.1']);
  });
});

describe('orcamento de IA', () => {
  it('exige chave e limites quando um provedor e habilitado', () => {
    expect(() =>
      loadEnv({ ...baseEnv, AI_PROVIDER: 'anthropic' } as NodeJS.ProcessEnv),
    ).toThrowError(/AI_API_KEY/);
  });

  it('exige orcamento diario maior que zero', () => {
    expect(() =>
      loadEnv({
        ...baseEnv,
        AI_PROVIDER: 'anthropic',
        AI_API_KEY: 'chave',
        AI_MONTHLY_USER_TOKEN_LIMIT: '1000',
      } as NodeJS.ProcessEnv),
    ).toThrowError(/AI_DAILY_BUDGET_CENTS/);
  });

  it('aceita IA desligada sem exigir nada', () => {
    expect(loadEnv(baseEnv as NodeJS.ProcessEnv).AI_PROVIDER).toBe('none');
  });
});

describe('redacao de logs', () => {
  it.each(['password', 'token', 'cpf', 'vin', 'plate', 'renavam', 'req.headers.authorization'])(
    'mantem %s na lista de campos censurados',
    (field) => {
      expect(REDACTED_PATHS).toContain(field);
    },
  );
});

describe('segregacao de roles (Fase 1A)', () => {
  it('recusa DATABASE_AUTH_URL que nao seja vlos_auth', () => {
    expect(() =>
      loadEnv({ ...baseEnv, DATABASE_AUTH_URL: 'postgres://vlos_app:x@localhost:5432/vlos' } as NodeJS.ProcessEnv),
    ).toThrowError(/vlos_auth/);
  });

  it('recusa a role de migracao no pool de autenticacao', () => {
    expect(() =>
      loadEnv({
        ...baseEnv,
        DATABASE_AUTH_URL: 'postgres://vlos_migrator:x@localhost:5432/vlos',
      } as NodeJS.ProcessEnv),
    ).toThrowError(/vlos_auth|migracao|RLS/);
  });

  it('exige AUTH_PEPPER em producao', () => {
    expect(() => loadEnv({ ...prodEnv, AUTH_PEPPER_BASE64: '' } as NodeJS.ProcessEnv)).toThrowError(
      /AUTH_PEPPER_BASE64/,
    );
  });

  it('recusa pepper de senha igual a KEK', () => {
    expect(() => loadEnv({ ...prodEnv, AUTH_PEPPER_BASE64: KEY_A } as NodeJS.ProcessEnv)).toThrowError(
      /diferente da KEK/,
    );
  });

  it('recusa cookie sem Secure em producao', () => {
    expect(() => loadEnv({ ...prodEnv, COOKIE_SECURE: 'false' } as NodeJS.ProcessEnv)).toThrowError(
      /COOKIE_SECURE/,
    );
  });
});
