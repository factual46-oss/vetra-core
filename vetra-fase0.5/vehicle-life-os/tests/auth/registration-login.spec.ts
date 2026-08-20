import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuthService, InvalidCredentialsError, WeakPasswordError } from '../../apps/api/src/modules/auth/application/auth.service.js';
import { AuthAuditService } from '../../apps/api/src/modules/auth/infra/auth-audit.service.js';
import { AuthDatabaseService } from '../../apps/api/src/modules/auth/infra/auth-database.service.js';
import { CredentialRepository } from '../../apps/api/src/modules/auth/infra/credential.repository.js';
import { JwtService } from '../../apps/api/src/modules/auth/infra/jwt.service.js';
import { PasswordHasherService } from '../../apps/api/src/modules/auth/infra/password-hasher.service.js';
import { RateLimitService } from '../../apps/api/src/modules/auth/infra/rate-limit.service.js';
import { RefreshTokenRepository } from '../../apps/api/src/modules/auth/infra/refresh-token.repository.js';
import { SessionRepository } from '../../apps/api/src/modules/auth/infra/session.repository.js';
import { DatabaseService } from '../../apps/api/src/infra/db/database.service.js';
import { RedisService } from '../../apps/api/src/infra/queue/redis.service.js';
import { InvalidEmailError } from '../../apps/api/src/modules/auth/domain/email.js';
import { cleanupUsers, requireDatabase, testSignals, uniqueEmail, withMigrator } from '../helpers/auth.js';

/** Sem skipIf: ausencia de banco e FALHA, nao skip. */
requireDatabase();

const PASSWORD = 'cavalo bateria grampo';

describe('cadastro e login', () => {
  let authDb: AuthDatabaseService;
  let db: DatabaseService;
  let redis: RedisService;
  let auth: AuthService;
  const created: string[] = [];

  beforeAll(() => {
    authDb = new AuthDatabaseService();
    db = new DatabaseService();
    redis = new RedisService();
    const hasher = new PasswordHasherService();
    const credentials = new CredentialRepository(authDb);
    const sessions = new SessionRepository(authDb, db);
    const refreshTokens = new RefreshTokenRepository(authDb);
    const audit = new AuthAuditService(authDb);
    auth = new AuthService(
      credentials,
      hasher,
      sessions,
      refreshTokens,
      new JwtService(),
      new RateLimitService(redis),
      audit,
    );
  });

  afterAll(async () => {
    await cleanupUsers(created);
    await authDb.onModuleDestroy();
    await db.onModuleDestroy();
    await redis.onModuleDestroy();
  });

  async function register(email: string, password = PASSWORD): Promise<string> {
    await auth.register({ email, password, displayName: 'Teste', signals: signals() });
    const id = await withMigrator(async (m) => {
      const r = await m.query<{ id: string }>(`SELECT id FROM identity."user" WHERE email = $1`, [
        email.trim().toLowerCase(),
      ]);
      return r.rows[0]?.id;
    });
    if (id) created.push(id);
    return id!;
  }

  /** IP unico por chamada: os testes nao podem se limitar uns aos outros. */
  function signals() {
    return { ...testSignals, ip: `198.51.100.${Math.floor(Math.random() * 250) + 1}` };
  }

  it('cria conta e credencial', async () => {
    const email = uniqueEmail('reg');
    const id = await register(email);
    expect(id).toBeTruthy();

    const hasCredential = await withMigrator(async (m) => {
      const r = await m.query(`SELECT 1 FROM identity.credential WHERE user_id = $1`, [id]);
      return r.rowCount;
    });
    expect(hasCredential).toBe(1);
  });

  it('nao armazena a senha nem em claro nem de forma reversivel', async () => {
    const email = uniqueEmail('hash');
    const id = await register(email);
    const stored = await withMigrator(async (m) => {
      const r = await m.query<{ password_hash: string; algorithm: string }>(
        `SELECT password_hash, algorithm FROM identity.credential WHERE user_id = $1`,
        [id],
      );
      return r.rows[0]!;
    });
    expect(stored.algorithm).toBe('argon2id');
    expect(stored.password_hash).toMatch(/^\$argon2id\$/);
    expect(stored.password_hash).not.toContain(PASSWORD);
  });

  it('e-mail duplicado NAO revela existencia: resposta identica', async () => {
    const email = uniqueEmail('dup');
    await register(email);
    // Segunda tentativa: sem erro, sem diferenca observavel.
    await expect(
      auth.register({ email, password: PASSWORD, displayName: 'Outro', signals: signals() }),
    ).resolves.toBeUndefined();

    const count = await withMigrator(async (m) => {
      const r = await m.query(`SELECT 1 FROM identity."user" WHERE email = $1`, [email.toLowerCase()]);
      return r.rowCount;
    });
    expect(count).toBe(1);
  });

  it('normaliza o e-mail no cadastro', async () => {
    const email = uniqueEmail('norm');
    await register(email.toUpperCase());
    const found = await withMigrator(async (m) => {
      const r = await m.query(`SELECT 1 FROM identity."user" WHERE email = $1`, [email.toLowerCase()]);
      return r.rowCount;
    });
    expect(found).toBe(1);
  });

  it('recusa senha fraca', async () => {
    await expect(
      auth.register({ email: uniqueEmail('weak'), password: 'curta', displayName: 'X', signals: signals() }),
    ).rejects.toBeInstanceOf(WeakPasswordError);
  });

  it('recusa e-mail invalido', async () => {
    await expect(
      auth.register({ email: 'sem-arroba', password: PASSWORD, displayName: 'X', signals: signals() }),
    ).rejects.toBeInstanceOf(InvalidEmailError);
  });

  it('login valido emite access token, refresh token e sessao', async () => {
    const email = uniqueEmail('login');
    await register(email);
    const issued = await auth.login({ email, password: PASSWORD, signals: signals() });

    expect(issued.accessToken.split('.')).toHaveLength(3);
    expect(issued.refreshToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(issued.sessionId).toMatch(/^[0-9a-f-]{36}$/);
    expect(issued.expiresInSeconds).toBe(600);
  });

  it('login aceita e-mail em qualquer caixa', async () => {
    const email = uniqueEmail('caixa');
    await register(email);
    await expect(
      auth.login({ email: email.toUpperCase(), password: PASSWORD, signals: signals() }),
    ).resolves.toBeTruthy();
  });

  it('recusa senha incorreta', async () => {
    const email = uniqueEmail('badpass');
    await register(email);
    await expect(
      auth.login({ email, password: 'senha completamente errada', signals: signals() }),
    ).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it('recusa conta inexistente', async () => {
    await expect(
      auth.login({ email: uniqueEmail('fantasma'), password: PASSWORD, signals: signals() }),
    ).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it('ANTI-ENUMERACAO: conta inexistente e senha errada produzem erro identico', async () => {
    const email = uniqueEmail('enum');
    await register(email);

    const errors: unknown[] = [];
    for (const attempt of [
      { email, password: 'senha errada mesmo' },
      { email: uniqueEmail('nao-existe'), password: PASSWORD },
      { email: 'formato-invalido', password: PASSWORD },
    ]) {
      try {
        await auth.login({ ...attempt, signals: signals() });
      } catch (err) {
        errors.push(err);
      }
    }

    expect(errors).toHaveLength(3);
    const shapes = errors.map((e) => `${(e as Error).name}:${(e as Error).message}`);
    expect(new Set(shapes).size).toBe(1);
  });

  it('recusa login de conta bloqueada, com o mesmo erro generico', async () => {
    const email = uniqueEmail('blocked');
    const id = await register(email);
    await withMigrator((m) => m.query(`UPDATE identity."user" SET blocked_at = now() WHERE id = $1`, [id]));

    await expect(auth.login({ email, password: PASSWORD, signals: signals() })).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
  });

  it('conta bloqueada nao vaza pelo tempo de resposta: a senha e verificada antes', async () => {
    const email = uniqueEmail('blocked2');
    const id = await register(email);
    await withMigrator((m) => m.query(`UPDATE identity."user" SET blocked_at = now() WHERE id = $1`, [id]));

    // Se o bloqueio cortasse antes do Argon2, esta chamada seria ordens de
    // grandeza mais rapida que um login normal. Verificamos que nao e.
    const started = Date.now();
    await auth.login({ email, password: PASSWORD, signals: signals() }).catch(() => undefined);
    expect(Date.now() - started).toBeGreaterThan(10);
  });

  it('re-hash automatico quando os parametros do banco sao mais fracos que os atuais', async () => {
    const email = uniqueEmail('rehash');
    const id = await register(email);

    await withMigrator((m) =>
      m.query(`UPDATE identity.credential SET params = '{"memoryKiB":19456,"timeCost":1,"parallelism":1}'::jsonb WHERE user_id = $1`, [id]),
    );

    await auth.login({ email, password: PASSWORD, signals: signals() });

    const params = await withMigrator(async (m) => {
      const r = await m.query<{ params: { timeCost: number } }>(
        `SELECT params FROM identity.credential WHERE user_id = $1`,
        [id],
      );
      return r.rows[0]!.params;
    });
    expect(params.timeCost).toBeGreaterThanOrEqual(2);
  });

  it('re-hash NAO altera password_changed_at: endurecer parametro nao e trocar senha', async () => {
    const email = uniqueEmail('rehash2');
    const id = await register(email);
    const before = await withMigrator(async (m) => {
      const r = await m.query<{ password_changed_at: Date }>(
        `SELECT password_changed_at FROM identity.credential WHERE user_id = $1`, [id]);
      return r.rows[0]!.password_changed_at;
    });

    await withMigrator((m) =>
      m.query(`UPDATE identity.credential SET params = '{"memoryKiB":19456,"timeCost":1,"parallelism":1}'::jsonb WHERE user_id = $1`, [id]),
    );
    await auth.login({ email, password: PASSWORD, signals: signals() });

    const after = await withMigrator(async (m) => {
      const r = await m.query<{ password_changed_at: Date }>(
        `SELECT password_changed_at FROM identity.credential WHERE user_id = $1`, [id]);
      return r.rows[0]!.password_changed_at;
    });
    expect(after.getTime()).toBe(before.getTime());
  });

  it('registra os eventos de auditoria esperados, sem segredo', async () => {
    const email = uniqueEmail('audit');
    const id = await register(email);
    await auth.login({ email, password: PASSWORD, signals: signals() });
    await auth.login({ email, password: 'errada demais', signals: signals() }).catch(() => undefined);

    const events = await withMigrator(async (m) => {
      const r = await m.query<{ action: string; metadata: unknown }>(
        `SELECT action, metadata FROM audit.log WHERE actor_user_id = $1 ORDER BY id`,
        [id],
      );
      return r.rows;
    });

    const actions = events.map((e) => e.action);
    expect(actions).toContain('AUTH_REGISTERED');
    expect(actions).toContain('AUTH_LOGIN_SUCCEEDED');
    expect(actions).toContain('AUTH_LOGIN_FAILED');

    const dump = JSON.stringify(events);
    expect(dump).not.toContain(PASSWORD);
    expect(dump).not.toContain('$argon2id$');
  });
});
