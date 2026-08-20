import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuthService } from '../../apps/api/src/modules/auth/application/auth.service.js';
import { InvalidRefreshTokenError, RefreshService } from '../../apps/api/src/modules/auth/application/refresh.service.js';
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
import { cleanupUsers, requireDatabase, testSignals, uniqueEmail, withMigrator } from '../helpers/auth.js';

requireDatabase();
const PASSWORD = 'cavalo bateria grampo';

describe('rotacao de refresh token e deteccao de replay', () => {
  let authDb: AuthDatabaseService;
  let db: DatabaseService;
  let redis: RedisService;
  let auth: AuthService;
  let refresh: RefreshService;
  let sessions: SessionRepository;
  const created: string[] = [];

  beforeAll(() => {
    authDb = new AuthDatabaseService();
    db = new DatabaseService();
    redis = new RedisService();
    const credentials = new CredentialRepository(authDb);
    const refreshTokens = new RefreshTokenRepository(authDb);
    const jwt = new JwtService();
    const rateLimit = new RateLimitService(redis);
    const audit = new AuthAuditService(authDb);
    sessions = new SessionRepository(authDb, db);
    auth = new AuthService(credentials, new PasswordHasherService(), sessions, refreshTokens, jwt, rateLimit, audit);
    refresh = new RefreshService(refreshTokens, sessions, jwt, audit, rateLimit, authDb);
  });

  afterAll(async () => {
    await cleanupUsers(created);
    await authDb.onModuleDestroy();
    await db.onModuleDestroy();
    await redis.onModuleDestroy();
  });

  function signals() {
    return { ...testSignals, ip: `198.51.100.${Math.floor(Math.random() * 250) + 1}` };
  }

  async function newUserSession() {
    const email = uniqueEmail('rt');
    await auth.register({ email, password: PASSWORD, displayName: 'RT', signals: signals() });
    const id = await withMigrator(async (m) => {
      const r = await m.query<{ id: string }>(`SELECT id FROM identity."user" WHERE email = $1`, [email]);
      return r.rows[0]!.id;
    });
    created.push(id);
    const issued = await auth.login({ email, password: PASSWORD, signals: signals() });
    return { userId: id, issued };
  }

  it('rotaciona: devolve token novo, diferente do anterior', async () => {
    const { issued } = await newUserSession();
    const rotated = await refresh.rotate({ rawToken: issued.refreshToken, signals: signals() });
    expect(rotated.refreshToken).not.toBe(issued.refreshToken);
    expect(rotated.sessionId).toBe(issued.sessionId);
    expect(rotated.accessToken.split('.')).toHaveLength(3);
  });

  it('o token anterior deixa de funcionar apos a rotacao', async () => {
    const { issued } = await newUserSession();
    await refresh.rotate({ rawToken: issued.refreshToken, signals: signals() });
    await expect(refresh.rotate({ rawToken: issued.refreshToken, signals: signals() })).rejects.toBeInstanceOf(
      InvalidRefreshTokenError,
    );
  });

  it('REPLAY: reutilizar token ja consumido revoga a FAMILIA inteira', async () => {
    const { issued } = await newUserSession();
    const second = await refresh.rotate({ rawToken: issued.refreshToken, signals: signals() });

    await expect(refresh.rotate({ rawToken: issued.refreshToken, signals: signals() })).rejects.toMatchObject({
      replayDetected: true,
    });

    // O token que era valido tambem morre: a cadeia inteira e considerada suspeita.
    await expect(refresh.rotate({ rawToken: second.refreshToken, signals: signals() })).rejects.toBeInstanceOf(
      InvalidRefreshTokenError,
    );
  });

  it('replay encerra a sessao e registra auditoria', async () => {
    const { userId, issued } = await newUserSession();
    await refresh.rotate({ rawToken: issued.refreshToken, signals: signals() });
    await refresh.rotate({ rawToken: issued.refreshToken, signals: signals() }).catch(() => undefined);

    const state = await withMigrator(async (m) => {
      const session = await m.query<{ revoked_reason: string }>(
        `SELECT revoked_reason FROM identity.session WHERE id = $1`, [issued.sessionId]);
      const audit = await m.query<{ action: string }>(
        `SELECT action FROM audit.log WHERE actor_user_id = $1 AND action = 'AUTH_REFRESH_REPLAY_DETECTED'`, [userId]);
      return { reason: session.rows[0]?.revoked_reason, replayEvents: audit.rowCount };
    });

    expect(state.reason).toBe('REPLAY_DETECTED');
    expect(state.replayEvents).toBeGreaterThanOrEqual(1);
  });

  it('CONCORRENCIA: duas requisicoes simultaneas com o mesmo token -- exatamente uma vence', async () => {
    // Repetido para pegar instabilidade: corrida que passa uma vez nao prova nada.
    for (let round = 0; round < 20; round++) {
      const { issued } = await newUserSession();

      const results = await Promise.allSettled([
        refresh.rotate({ rawToken: issued.refreshToken, signals: signals() }),
        refresh.rotate({ rawToken: issued.refreshToken, signals: signals() }),
      ]);

      const winners = results.filter((r) => r.status === 'fulfilled');
      const losers = results.filter((r) => r.status === 'rejected');

      expect(winners).toHaveLength(1);
      expect(losers).toHaveLength(1);
      expect((losers[0] as PromiseRejectedResult).reason).toBeInstanceOf(InvalidRefreshTokenError);
    }
  });

  it('o token BRUTO nunca e persistido em coluna alguma', async () => {
    const { issued } = await newUserSession();

    const leaked = await withMigrator(async (m) => {
      // Varre todas as colunas da tabela como texto, procurando o valor bruto.
      const r = await m.query<{ found: string }>(
        `SELECT t::text AS found FROM identity.refresh_token t WHERE t::text LIKE '%' || $1 || '%'`,
        [issued.refreshToken],
      );
      return r.rowCount;
    });

    expect(leaked).toBe(0);
  });

  it('o hash armazenado corresponde ao sha256 do token bruto', async () => {
    const { issued } = await newUserSession();
    const match = await withMigrator(async (m) => {
      const r = await m.query(
        `SELECT 1 FROM identity.refresh_token WHERE token_hash = extensions.digest($1, 'sha256')`,
        [issued.refreshToken],
      );
      return r.rowCount;
    });
    expect(match).toBe(1);
  });

  it('recusa token inexistente', async () => {
    await expect(
      refresh.rotate({ rawToken: 'A'.repeat(43), signals: signals() }),
    ).rejects.toBeInstanceOf(InvalidRefreshTokenError);
  });

  it('recusa token de formato invalido sem tocar no banco', async () => {
    await expect(refresh.rotate({ rawToken: 'curto', signals: signals() })).rejects.toMatchObject({
      replayDetected: false,
    });
  });

  it('recusa refresh quando a sessao foi revogada', async () => {
    const { issued } = await newUserSession();
    await sessions.revoke(issued.sessionId, 'TESTE');
    await expect(refresh.rotate({ rawToken: issued.refreshToken, signals: signals() })).rejects.toBeInstanceOf(
      InvalidRefreshTokenError,
    );
  });

  it('recusa token expirado', async () => {
    const { issued } = await newUserSession();
    await withMigrator((m) =>
      m.query(`UPDATE identity.refresh_token SET expires_at = now() - interval '1 day' WHERE session_id = $1`, [
        issued.sessionId,
      ]),
    );
    await expect(refresh.rotate({ rawToken: issued.refreshToken, signals: signals() })).rejects.toBeInstanceOf(
      InvalidRefreshTokenError,
    );
  });

  it('mantem a mesma familia ao longo da cadeia de rotacoes', async () => {
    const { issued } = await newUserSession();
    let current = issued.refreshToken;
    for (let i = 0; i < 3; i++) {
      current = (await refresh.rotate({ rawToken: current, signals: signals() })).refreshToken;
    }
    const families = await withMigrator(async (m) => {
      const r = await m.query<{ family_id: string }>(
        `SELECT DISTINCT family_id FROM identity.refresh_token WHERE session_id = $1`,
        [issued.sessionId],
      );
      return r.rowCount;
    });
    expect(families).toBe(1);
  });
});
