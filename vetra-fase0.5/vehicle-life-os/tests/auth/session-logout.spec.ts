import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuthService } from '../../apps/api/src/modules/auth/application/auth.service.js';
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

describe('sessoes e logout', () => {
  let authDb: AuthDatabaseService;
  let db: DatabaseService;
  let redis: RedisService;
  let auth: AuthService;
  let sessions: SessionRepository;
  const created: string[] = [];

  beforeAll(() => {
    authDb = new AuthDatabaseService();
    db = new DatabaseService();
    redis = new RedisService();
    sessions = new SessionRepository(authDb, db);
    auth = new AuthService(
      new CredentialRepository(authDb),
      new PasswordHasherService(),
      sessions,
      new RefreshTokenRepository(authDb),
      new JwtService(),
      new RateLimitService(redis),
      new AuthAuditService(authDb),
    );
  });

  afterAll(async () => {
    await cleanupUsers(created);
    await Promise.all([authDb.onModuleDestroy(), db.onModuleDestroy(), redis.onModuleDestroy()]);
  });

  function signals() {
    return { ...testSignals, ip: `198.51.100.${Math.floor(Math.random() * 250) + 1}` };
  }

  async function user(prefix: string) {
    const email = uniqueEmail(prefix);
    await auth.register({ email, password: PASSWORD, displayName: prefix, signals: signals() });
    const id = await withMigrator(async (m) => {
      const r = await m.query<{ id: string }>(`SELECT id FROM identity."user" WHERE email = $1`, [email]);
      return r.rows[0]!.id;
    });
    created.push(id);
    return { id, email };
  }

  it('login cria sessao ativa e vinculada ao usuario', async () => {
    const u = await user('s1');
    const issued = await auth.login({ email: u.email, password: PASSWORD, signals: signals() });
    expect(await sessions.isActiveForUser(issued.sessionId, u.id)).toBe(true);
  });

  it('sessao de A nao e valida para B', async () => {
    const a = await user('s2a');
    const b = await user('s2b');
    const issued = await auth.login({ email: a.email, password: PASSWORD, signals: signals() });
    expect(await sessions.isActiveForUser(issued.sessionId, b.id)).toBe(false);
  });

  it('nao guarda IP nem user agent em claro', async () => {
    const u = await user('s3');
    const issued = await auth.login({ email: u.email, password: PASSWORD, signals: signals() });
    const row = await withMigrator(async (m) => {
      const r = await m.query<{ ip_hash: Buffer | null; user_agent_hash: Buffer | null }>(
        `SELECT ip_hash, user_agent_hash FROM identity.session WHERE id = $1`, [issued.sessionId]);
      return r.rows[0]!;
    });
    expect(row.ip_hash).toHaveLength(32);
    expect(row.ip_hash?.toString('utf8')).not.toContain('198.51.100');
    expect(row.user_agent_hash).toHaveLength(32);
  });

  it('logout revoga a sessao e os tokens dela', async () => {
    const u = await user('s4');
    const issued = await auth.login({ email: u.email, password: PASSWORD, signals: signals() });
    await auth.logout({ userId: u.id, sessionId: issued.sessionId, signals: signals() });

    expect(await sessions.isActiveForUser(issued.sessionId, u.id)).toBe(false);
    const revokedTokens = await withMigrator(async (m) => {
      const r = await m.query(
        `SELECT 1 FROM identity.refresh_token WHERE session_id = $1 AND revoked_at IS NOT NULL`, [issued.sessionId]);
      return r.rowCount;
    });
    expect(revokedTokens).toBeGreaterThanOrEqual(1);
  });

  it('sessao expirada deixa de ser ativa', async () => {
    const u = await user('s5');
    const issued = await auth.login({ email: u.email, password: PASSWORD, signals: signals() });
    await withMigrator((m) =>
      m.query(`UPDATE identity.session SET expires_at = now() - interval '1 hour' WHERE id = $1`, [issued.sessionId]));
    expect(await sessions.isActiveForUser(issued.sessionId, u.id)).toBe(false);
  });

  it('listOwn devolve apenas as sessoes do proprio usuario', async () => {
    const a = await user('s6a');
    const b = await user('s6b');
    await auth.login({ email: a.email, password: PASSWORD, signals: signals() });
    await auth.login({ email: a.email, password: PASSWORD, signals: signals() });
    await auth.login({ email: b.email, password: PASSWORD, signals: signals() });

    const ofA = await sessions.listOwn(a.id);
    const ofB = await sessions.listOwn(b.id);
    expect(ofA).toHaveLength(2);
    expect(ofB).toHaveLength(1);
    expect(ofA.every((s) => s.userId === a.id)).toBe(true);
  });

  it('logout-all encerra todas as sessoes do usuario e nenhuma de outro', async () => {
    const a = await user('s7a');
    const b = await user('s7b');
    await auth.login({ email: a.email, password: PASSWORD, signals: signals() });
    await auth.login({ email: a.email, password: PASSWORD, signals: signals() });
    const sessionB = await auth.login({ email: b.email, password: PASSWORD, signals: signals() });

    const revoked = await auth.logoutAll({ userId: a.id, signals: signals() });
    expect(revoked).toBe(2);
    expect(await sessions.listOwn(a.id)).toHaveLength(0);
    expect(await sessions.isActiveForUser(sessionB.sessionId, b.id)).toBe(true);
  });

  it('registra auditoria de logout', async () => {
    const u = await user('s8');
    const issued = await auth.login({ email: u.email, password: PASSWORD, signals: signals() });
    await auth.logout({ userId: u.id, sessionId: issued.sessionId, signals: signals() });

    const events = await withMigrator(async (m) => {
      const r = await m.query<{ action: string }>(
        `SELECT action FROM audit.log WHERE actor_user_id = $1 AND action = 'AUTH_LOGOUT'`, [u.id]);
      return r.rowCount;
    });
    expect(events).toBe(1);
  });
});
