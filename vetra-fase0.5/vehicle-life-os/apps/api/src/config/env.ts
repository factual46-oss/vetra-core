import { z } from 'zod';

/**
 * Validacao de ambiente.
 *
 * AUD-06 (ALTO, corrigido): antes existia `export const env = loadEnv()` no topo
 * do modulo. Qualquer import -- inclusive de um arquivo de teste -- disparava a
 * validacao no momento do import, o que quebrava a suite inteira em qualquer
 * processo sem DATABASE_URL. Agora a resolucao e preguicosa e memoizada.
 */

const base64Key = (bytes: number) =>
  z
    .string()
    .refine((v) => Buffer.from(v, 'base64').length === bytes, `deve ser base64 de ${bytes} bytes`);

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    API_PORT: z.coerce.number().int().positive().default(3000),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
    CORS_ORIGINS: z.string().default(''),

    /**
     * AUD-07: lista de proxies confiaveis. Vazio = nao confiar em nenhum header
     * de proxy. Nunca `true` incondicional: se a API puder ser alcancada
     * diretamente, qualquer cliente forja X-Forwarded-For e derruba o rate
     * limiting por IP e a atribuicao de origem no log de auditoria.
     */
    TRUSTED_PROXIES: z.string().default(''),

    DATABASE_URL: z.string().url(),
    DATABASE_POOL_MAX: z.coerce.number().int().positive().default(10),

    /**
     * Fase 1A / Alternativa B: pool separado com a role vlos_auth, usada
     * exclusivamente pelo modulo de autenticacao. Ela nao tem privilegio sobre
     * tabela alguma alem de session e refresh_token, e e a unica que executa as
     * funcoes de credencial.
     */
    DATABASE_AUTH_URL: z.string().url(),
    DATABASE_AUTH_POOL_MAX: z.coerce.number().int().positive().default(5),

    REDIS_URL: z.string().url(),

    APP_KEK_BASE64: base64Key(32).or(z.literal('')).default(''),
    IDENTIFIER_PEPPER_BASE64: base64Key(32).or(z.literal('')).default(''),
    AUDIT_IP_HASH_KEY_BASE64: base64Key(32).or(z.literal('')).default(''),

    // --- Fase 1A: autenticacao -------------------------------------------
    /**
     * Pepper aplicado por HMAC antes do Argon2. Vive apenas na memoria da
     * aplicacao. E o que faz um hash extraido do banco nao valer nada para
     * ataque offline. Perde-lo invalida todas as senhas -- material critico de
     * backup, com custodia propria.
     */
    AUTH_PEPPER_BASE64: base64Key(32).or(z.literal('')).default(''),

    /** Conjunto de chaves EdDSA. Ver domain/jwt-keyset.ts. */
    JWT_KEYS_JSON: z.string().default('[]'),
    JWT_ISSUER: z.string().default('vetra'),
    JWT_AUDIENCE: z.string().default('vetra-api'),
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().max(3600).default(600),
    REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().positive().max(90).default(30),
    SESSION_TTL_DAYS: z.coerce.number().int().positive().max(90).default(30),

    /**
     * Argon2id. Minimo OWASP: m >= 19456 KiB, t >= 2, p >= 1.
     * Os valores finais devem sair do benchmark no hardware real
     * (tools/bench-argon2.mjs), nao deste padrao.
     */
    ARGON2_MEMORY_KIB: z.coerce.number().int().min(19456).default(19456),
    ARGON2_TIME_COST: z.coerce.number().int().min(2).default(3),
    ARGON2_PARALLELISM: z.coerce.number().int().min(1).max(16).default(1),

    COOKIE_SECURE: z
      .enum(['true', 'false'])
      .default('true')
      .transform((v) => v === 'true'),
    COOKIE_DOMAIN: z.string().default(''),

    /** Um unico provedor de IA no MVP (gate item 31). `none` = IA desligada. */
    AI_PROVIDER: z.enum(['none', 'anthropic', 'openai', 'google', 'local']).default('none'),
    AI_API_KEY: z.string().default(''),
    AI_DAILY_BUDGET_CENTS: z.coerce.number().int().nonnegative().default(0),
    AI_MONTHLY_USER_TOKEN_LIMIT: z.coerce.number().int().nonnegative().default(0),
    AI_REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().default(30_000),
  })
  .superRefine((env, ctx) => {
    const fail = (path: string, message: string) =>
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: [path], message });

    /**
     * AUD-08 (CRITICO se ocorresse em producao): a aplicacao jamais pode
     * conectar com a role de migracao. vlos_migrator e dona das tabelas e
     * portanto NAO e submetida as policies de RLS -- conectar com ela desliga,
     * em silencio, todo o isolamento entre usuarios.
     */
    if (/(^|[:/@])vlos_migrator([:@]|$)/.test(env.DATABASE_URL)) {
      fail(
        'DATABASE_URL',
        'a aplicacao nao pode conectar como vlos_migrator: a role dona nao e submetida a RLS. Use vlos_app.',
      );
    }

    if (env.AI_PROVIDER !== 'none') {
      if (env.AI_API_KEY === '') fail('AI_API_KEY', `obrigatoria quando AI_PROVIDER=${env.AI_PROVIDER}`);
      if (env.AI_DAILY_BUDGET_CENTS === 0)
        fail('AI_DAILY_BUDGET_CENTS', 'orcamento diario deve ser > 0 quando a IA esta habilitada');
      if (env.AI_MONTHLY_USER_TOKEN_LIMIT === 0)
        fail('AI_MONTHLY_USER_TOKEN_LIMIT', 'limite por usuario deve ser > 0 quando a IA esta habilitada');
    }

    // A aplicacao de auth nao pode usar a role generica, e vice-versa:
    // trocar as duas desfaria a segregacao da Alternativa B em silencio.
    if (!/(^|[:/@])vlos_auth([:@]|$)/.test(env.DATABASE_AUTH_URL)) {
      fail('DATABASE_AUTH_URL', 'deve conectar como vlos_auth');
    }
    if (/(^|[:/@])vlos_migrator([:@]|$)/.test(env.DATABASE_AUTH_URL)) {
      fail('DATABASE_AUTH_URL', 'a role de migracao nao e submetida a RLS. Use vlos_auth.');
    }

    if (env.NODE_ENV !== 'production') return;

    if (env.AUTH_PEPPER_BASE64 === '') {
      fail('AUTH_PEPPER_BASE64', 'obrigatorio em producao: sem pepper, hash extraido do banco e crackavel offline');
    }
    if (env.AUTH_PEPPER_BASE64 !== '' && env.AUTH_PEPPER_BASE64 === env.APP_KEK_BASE64) {
      fail('AUTH_PEPPER_BASE64', 'o pepper de senha deve ser diferente da KEK');
    }
    if (!env.COOKIE_SECURE) {
      fail('COOKIE_SECURE', 'cookie sem Secure em producao trafega em claro');
    }

    for (const key of ['APP_KEK_BASE64', 'IDENTIFIER_PEPPER_BASE64', 'AUDIT_IP_HASH_KEY_BASE64'] as const) {
      if (env[key] === '') fail(key, 'obrigatoria em producao');
    }
    if (env.APP_KEK_BASE64 !== '' && env.APP_KEK_BASE64 === env.IDENTIFIER_PEPPER_BASE64) {
      fail('IDENTIFIER_PEPPER_BASE64', 'o pepper do indice cego deve ser diferente da KEK (Doc 03, secao 4)');
    }
    if (env.CORS_ORIGINS === '') {
      fail('CORS_ORIGINS', 'defina as origens permitidas em producao (vazio bloqueia o cliente web)');
    }
  });

export type Env = z.infer<typeof schema>;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = schema.safeParse(source);
  if (!parsed.success) {
    const detail = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Configuracao invalida:\n${detail}`);
  }
  return parsed.data;
}

let cached: Env | undefined;

/** Resolve e memoiza a configuracao. Falha rapido, mas so quando alguem precisa dela. */
export function getEnv(): Env {
  cached ??= loadEnv();
  return cached;
}

/** Apenas para testes: descarta a memoizacao. */
export function resetEnvCache(): void {
  cached = undefined;
}

/**
 * Lista de proxies confiaveis para o Fastify.
 * Retorna `false` (nao confiar em ninguem) quando nada foi configurado.
 */
export function trustProxySetting(env: Env = getEnv()): string[] | false {
  const list = env.TRUSTED_PROXIES.split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  return list.length > 0 ? list : false;
}
