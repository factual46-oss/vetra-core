import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ExecutionContext } from '@nestjs/common';
import { AuthService } from '../../apps/api/src/modules/auth/application/auth.service.js';
import { ReauthFailedError, ReauthService } from '../../apps/api/src/modules/auth/application/reauth.service.js';
import { AuthAuditService } from '../../apps/api/src/modules/auth/infra/auth-audit.service.js';
import { AuthDatabaseService } from '../../apps/api/src/modules/auth/infra/auth-database.service.js';
import { CredentialRepository } from '../../apps/api/src/modules/auth/infra/credential.repository.js';
import { JwtService } from '../../apps/api/src/modules/auth/infra/jwt.service.js';
import { PasswordHasherService } from '../../apps/api/src/modules/auth/infra/password-hasher.service.js';
import { RateLimitService } from '../../apps/api/src/modules/auth/infra/rate-limit.service.js';
import { RefreshTokenRepository } from '../../apps/api/src/modules/auth/infra/refresh-token.repository.js';
import { SessionRepository } from '../../apps/api/src/modules/auth/infra/session.repository.js';
import {
  REAUTH_WINDOW_SECONDS,
  RecentAuthGuard,
} from '../../apps/api/src/modules/auth/guards/recent-auth.guard.js';
import type { AuthContext } from '../../apps/api/src/modules/auth/guards/auth.guard.js';
import { DatabaseService } from '../../apps/api/src/infra/db/database.service.js';
import { RedisService } from '../../apps/api/src/infra/queue/redis.service.js';
import { APP_URL, connect, expectRejection } from '../helpers/db.js';
import { cleanupUsers, requireDatabase, testSignals, uniqueEmail, withMigrator } from '../helpers/auth.js';

/**
 * Bloco 3 — janela de reautenticacao (sudo mode).
 *
 * A tese: uma sessao roubada e uma sessao VALIDA. Sem esta barreira, um access
 * token furtado bastaria para cadastrar ou remover o segundo fator no Bloco 5.
 *
 * O guard e exercitado com um ExecutionContext minimo. Isso nao substitui
 * seguranca de banco: a consulta continua indo ao PostgreSQL real, sob RLS.
 */
requireDatabase();

const PASSWORD = 'cavalo bateria grampo';

/** ExecutionContext minimo, apenas com o que o guard le. */
function contextoDe(auth: AuthContext | undefined): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ auth }) }),
  } as unknown as ExecutionContext;
}

describe('reautenticacao (sudo mode)', () => {
  let authDb: AuthDatabaseService;
  let db: DatabaseService;
  let redis: RedisService;
  let auth: AuthService;
  let reauth: ReauthService;
  let sessions: SessionRepository;
  let guard: RecentAuthGuard;
  const criados: string[] = [];

  beforeAll(() => {
    authDb = new AuthDatabaseService();
    db = new DatabaseService();
    redis = new RedisService();
    const credentials = new CredentialRepository(authDb);
    const hasher = new PasswordHasherService();
    const rateLimit = new RateLimitService(redis);
    const audit = new AuthAuditService(authDb);
    sessions = new SessionRepository(authDb, db);

    auth = new AuthService(
      credentials,
      hasher,
      sessions,
      new RefreshTokenRepository(authDb),
      new JwtService(),
      rateLimit,
      audit,
    );
    reauth = new ReauthService(credentials, hasher, sessions, db, authDb, rateLimit, audit);
    guard = new RecentAuthGuard(sessions);
  });

  afterAll(async () => {
    await cleanupUsers(criados);
    await Promise.all([authDb.onModuleDestroy(), db.onModuleDestroy(), redis.onModuleDestroy()]);
  });

  function signals() {
    return { ...testSignals, ip: `198.51.100.${Math.floor(Math.random() * 250) + 1}` };
  }

  async function novoUsuario(prefixo: string) {
    const email = uniqueEmail(prefixo);
    await auth.register({ email, password: PASSWORD, displayName: prefixo, signals: signals() });
    const userId = await withMigrator(async (m) => {
      const r = await m.query<{ id: string }>(`SELECT id FROM identity."user" WHERE email = $1`, [email]);
      return r.rows[0]!.id;
    });
    criados.push(userId);
    const sessao = await auth.login({ email, password: PASSWORD, signals: signals() });
    return { userId, email, sessionId: sessao.sessionId, accessToken: sessao.accessToken };
  }

  const lerReauth = (sessionId: string) =>
    withMigrator(async (m) => {
      const r = await m.query<{ reauthenticated_at: Date | null }>(
        `SELECT reauthenticated_at FROM identity.session WHERE id = $1`,
        [sessionId],
      );
      return r.rows[0]?.reauthenticated_at ?? null;
    });

  const contarTokens = (sessionId: string) =>
    withMigrator(async (m) => {
      const r = await m.query(`SELECT 1 FROM identity.refresh_token WHERE session_id = $1`, [sessionId]);
      return r.rowCount ?? 0;
    });

  // ── 1 ────────────────────────────────────────────────────────────────────
  it('1. sessao valida + senha correta abre a janela', async () => {
    const u = await novoUsuario('re1');
    expect(await lerReauth(u.sessionId)).toBeNull();

    const resultado = await reauth.reauthenticate({
      userId: u.userId,
      sessionId: u.sessionId,
      password: PASSWORD,
      signals: signals(),
    });

    expect(resultado.windowSeconds).toBe(REAUTH_WINDOW_SECONDS);
    expect(await lerReauth(u.sessionId)).toBeInstanceOf(Date);
  });

  // ── 2 ────────────────────────────────────────────────────────────────────
  it('2. senha incorreta e recusada e NAO altera reauthenticated_at', async () => {
    const u = await novoUsuario('re2');
    await reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() });
    const antes = await lerReauth(u.sessionId);

    await expect(
      reauth.reauthenticate({
        userId: u.userId,
        sessionId: u.sessionId,
        password: 'senha completamente errada',
        signals: signals(),
      }),
    ).rejects.toBeInstanceOf(ReauthFailedError);

    const depois = await lerReauth(u.sessionId);
    expect(depois?.getTime()).toBe(antes?.getTime());
  });

  // ── 3 e 14 ───────────────────────────────────────────────────────────────
  it('3. sessao revogada e recusada e nada e gravado', async () => {
    const u = await novoUsuario('re3');
    await sessions.revoke(u.sessionId, 'TESTE');

    await expect(
      reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() }),
    ).rejects.toBeInstanceOf(ReauthFailedError);

    expect(await lerReauth(u.sessionId)).toBeNull();
  });

  it('3b. sessao inexistente e recusada', async () => {
    const u = await novoUsuario('re3b');
    await expect(
      reauth.reauthenticate({
        userId: u.userId,
        sessionId: '00000000-0000-4000-8000-000000000000',
        password: PASSWORD,
        signals: signals(),
      }),
    ).rejects.toBeInstanceOf(ReauthFailedError);
  });

  it('14. sessao revogada DEPOIS de aberta a janela nao reabre', async () => {
    const u = await novoUsuario('re14');
    await reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() });
    await sessions.revoke(u.sessionId, 'TESTE');

    await expect(
      reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() }),
    ).rejects.toBeInstanceOf(ReauthFailedError);

    // E o guard tambem recusa, mesmo com o timestamp gravado.
    await expect(
      guard.canActivate(contextoDe({ userId: u.userId, sessionId: u.sessionId, amr: ['pwd'] })),
    ).rejects.toBeTruthy();
  });

  // ── 4, 5, 6 ──────────────────────────────────────────────────────────────
  it('4. sessao valida SEM reautenticacao e rejeitada pelo guard', async () => {
    const u = await novoUsuario('re4');
    await expect(
      guard.canActivate(contextoDe({ userId: u.userId, sessionId: u.sessionId, amr: ['pwd'] })),
    ).rejects.toMatchObject({ status: 403 });
  });

  it('5. reautenticacao recente (dentro de 5 min) e aceita', async () => {
    const u = await novoUsuario('re5');
    await reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() });

    await expect(
      guard.canActivate(contextoDe({ userId: u.userId, sessionId: u.sessionId, amr: ['pwd'] })),
    ).resolves.toBe(true);
  });

  it('5b. 4m59s ainda esta DENTRO da janela', async () => {
    const u = await novoUsuario('re5b');
    await reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() });
    await withMigrator((m) =>
      m.query(
        `UPDATE identity.session SET reauthenticated_at = now() - make_interval(secs => 299) WHERE id = $1`,
        [u.sessionId],
      ),
    );

    await expect(
      guard.canActivate(contextoDe({ userId: u.userId, sessionId: u.sessionId, amr: ['pwd'] })),
    ).resolves.toBe(true);
  });

  it('6. 5m01s ja esta FORA da janela', async () => {
    const u = await novoUsuario('re6');
    await reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() });
    await withMigrator((m) =>
      m.query(
        `UPDATE identity.session SET reauthenticated_at = now() - make_interval(secs => 301) WHERE id = $1`,
        [u.sessionId],
      ),
    );

    await expect(
      guard.canActivate(contextoDe({ userId: u.userId, sessionId: u.sessionId, amr: ['pwd'] })),
    ).rejects.toMatchObject({ status: 403 });
  });

  it('6b. exatamente 300s (a borda) ja esta fora: a comparacao e estrita', async () => {
    const u = await novoUsuario('re6b');
    await reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() });
    await withMigrator((m) =>
      m.query(
        `UPDATE identity.session SET reauthenticated_at = now() - make_interval(secs => $2) WHERE id = $1`,
        [u.sessionId, REAUTH_WINDOW_SECONDS],
      ),
    );

    await expect(
      guard.canActivate(contextoDe({ userId: u.userId, sessionId: u.sessionId, amr: ['pwd'] })),
    ).rejects.toBeTruthy();
  });

  it('o guard NAO renova a janela ao usa-la', async () => {
    // Renovar tornaria a janela perpetua para quem mantivesse a sessao ativa.
    const u = await novoUsuario('re-renova');
    await reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() });
    const antes = await lerReauth(u.sessionId);

    await guard.canActivate(contextoDe({ userId: u.userId, sessionId: u.sessionId, amr: ['pwd'] }));

    expect((await lerReauth(u.sessionId))?.getTime()).toBe(antes?.getTime());
  });

  // ── 7, 8, 9 ──────────────────────────────────────────────────────────────
  it('7 e 8. a janela pertence a SESSAO, nao ao usuario', async () => {
    const u = await novoUsuario('re7');
    const segunda = await auth.login({ email: u.email, password: PASSWORD, signals: signals() });

    await reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() });

    expect(await lerReauth(u.sessionId)).toBeInstanceOf(Date);
    // A segunda sessao do MESMO usuario nao herda a janela.
    expect(await lerReauth(segunda.sessionId)).toBeNull();
    await expect(
      guard.canActivate(contextoDe({ userId: u.userId, sessionId: segunda.sessionId, amr: ['pwd'] })),
    ).rejects.toBeTruthy();
  });

  it('9. usuario A nao abre a janela da sessao de B', async () => {
    const a = await novoUsuario('re9a');
    const b = await novoUsuario('re9b');

    // A tenta reautenticar informando o sessionId de B. A RLS de
    // identity.session nao devolve linha para o contexto de A.
    await expect(
      reauth.reauthenticate({
        userId: a.userId,
        sessionId: b.sessionId,
        password: PASSWORD,
        signals: signals(),
      }),
    ).rejects.toBeInstanceOf(ReauthFailedError);

    expect(await lerReauth(b.sessionId)).toBeNull();
  });

  it('9b. o guard nao aceita sid de outro usuario', async () => {
    const a = await novoUsuario('re9c');
    const b = await novoUsuario('re9d');
    await reauth.reauthenticate({ userId: b.userId, sessionId: b.sessionId, password: PASSWORD, signals: signals() });

    // Mesmo com a janela de B aberta, o contexto de A nao alcanca a sessao de B.
    await expect(
      guard.canActivate(contextoDe({ userId: a.userId, sessionId: b.sessionId, amr: ['pwd'] })),
    ).rejects.toBeTruthy();
  });

  // ── 10, 11, 12 ───────────────────────────────────────────────────────────
  it('10 e 11. nenhum token novo e emitido', async () => {
    const u = await novoUsuario('re10');
    const tokensAntes = await contarTokens(u.sessionId);

    const resultado = await reauth.reauthenticate({
      userId: u.userId,
      sessionId: u.sessionId,
      password: PASSWORD,
      signals: signals(),
    });

    // A resposta nao carrega credencial alguma.
    expect(Object.keys(resultado)).toEqual(['windowSeconds']);
    expect(await contarTokens(u.sessionId)).toBe(tokensAntes);
  });

  it('12. identidade e permissoes da sessao permanecem intactas', async () => {
    const u = await novoUsuario('re12');
    const antes = await withMigrator(async (m) => {
      const r = await m.query<{ user_id: string; amr: string[]; expires_at: Date }>(
        `SELECT user_id, amr, expires_at FROM identity.session WHERE id = $1`,
        [u.sessionId],
      );
      return r.rows[0]!;
    });

    await reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() });

    const depois = await withMigrator(async (m) => {
      const r = await m.query<{ user_id: string; amr: string[]; expires_at: Date }>(
        `SELECT user_id, amr, expires_at FROM identity.session WHERE id = $1`,
        [u.sessionId],
      );
      return r.rows[0]!;
    });

    expect(depois.user_id).toBe(antes.user_id);
    expect(depois.amr).toEqual(antes.amr);
    expect(depois.expires_at.getTime()).toBe(antes.expires_at.getTime());

    const admin = await db.withUserContext(u.userId, async (tx) => {
      const r = await tx.query(`SELECT 1 FROM identity.admin_permission`);
      return r.rowCount;
    });
    expect(admin).toBe(0);
  });

  // ── 13 ───────────────────────────────────────────────────────────────────
  it('13. reautenticacoes concorrentes em sessoes diferentes mantem isolamento', async () => {
    const a = await novoUsuario('re13a');
    const b = await novoUsuario('re13b');
    const c = await novoUsuario('re13c');

    await Promise.all([
      reauth.reauthenticate({ userId: a.userId, sessionId: a.sessionId, password: PASSWORD, signals: signals() }),
      reauth.reauthenticate({ userId: b.userId, sessionId: b.sessionId, password: PASSWORD, signals: signals() }),
    ]);

    expect(await lerReauth(a.sessionId)).toBeInstanceOf(Date);
    expect(await lerReauth(b.sessionId)).toBeInstanceOf(Date);
    // C nao participou: nao pode ter sido afetado por escrita ampla demais.
    expect(await lerReauth(c.sessionId)).toBeNull();
  });

  // ── auditoria ────────────────────────────────────────────────────────────
  it('registra sucesso e falha na auditoria, sem material sensivel', async () => {
    const u = await novoUsuario('re-audit');
    await reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() });
    await reauth
      .reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: 'errada demais', signals: signals() })
      .catch(() => undefined);

    const eventos = await withMigrator(async (m) => {
      const r = await m.query<{ action: string; metadata: unknown; reason: string | null }>(
        `SELECT action, metadata, reason FROM audit.log WHERE actor_user_id = $1 AND action LIKE 'AUTH_REAUTH%'`,
        [u.userId],
      );
      return r.rows;
    });

    expect(eventos.map((e) => e.action)).toContain('AUTH_REAUTH_SUCCEEDED');
    expect(eventos.map((e) => e.action)).toContain('AUTH_REAUTH_FAILED');

    const dump = JSON.stringify(eventos);
    expect(dump).not.toContain(PASSWORD);
    expect(dump).not.toContain('$argon2id$');
    expect(dump).not.toContain('errada demais');
  });

  // ── Bloco 3.5: a escrita nao e alcancavel por vlos_app ───────────────────
  it('vlos_app NAO consegue escrever reauthenticated_at diretamente', async () => {
    // Esta era a cadeia que a 0016 quebrou: token roubado + SQL injection em
    // QUALQUER modulo que use vlos_app abriria a janela e permitiria desativar
    // o segundo fator. Agora a role generica nao tem UPDATE nesta tabela.
    const u = await novoUsuario('re-app');
    const app = connect(APP_URL!);
    await app.connect();
    try {
      const err = await expectRejection(() =>
        app.query(`UPDATE identity.session SET reauthenticated_at = now() WHERE id = $1`, [u.sessionId]),
      );
      expect(err.message).toMatch(/permission denied|permissão negada/i);
      expect(await lerReauth(u.sessionId)).toBeNull();
    } finally {
      await app.end();
    }
  });

  it('vlos_app NAO consegue nenhuma mutacao em identity.session', async () => {
    const u = await novoUsuario('re-app2');
    const app = connect(APP_URL!);
    await app.connect();
    try {
      for (const sql of [
        `UPDATE identity.session SET revoked_at = now() WHERE id = $1`,
        `UPDATE identity.session SET expires_at = now() + interval '10 years' WHERE id = $1`,
        `UPDATE identity.session SET amr = ARRAY['pwd','otp'] WHERE id = $1`,
      ]) {
        const err = await expectRejection(() => app.query(sql, [u.sessionId]));
        expect(err.message).toMatch(/permission denied|permissão negada/i);
      }
    } finally {
      await app.end();
    }
  });

  it('vlos_app MANTEM a leitura: o AuthGuard e o RecentAuthGuard dependem dela', async () => {
    const u = await novoUsuario('re-app3');
    await reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() });

    expect(await sessions.isActiveForUser(u.sessionId, u.userId)).toBe(true);
    await expect(
      guard.canActivate(contextoDe({ userId: u.userId, sessionId: u.sessionId, amr: ['pwd'] })),
    ).resolves.toBe(true);
  });

  it('a escrita exige o par (id, user_id) estritamente correto', async () => {
    // Terceira camada: mesmo pelo pool vlos_auth, que opera com USING (true),
    // o WHERE amarra sessao e dono.
    const a = await novoUsuario('re35a');
    const b = await novoUsuario('re35b');

    await expect(
      reauth.reauthenticate({
        userId: a.userId,
        sessionId: b.sessionId,
        password: PASSWORD,
        signals: signals(),
      }),
    ).rejects.toBeInstanceOf(ReauthFailedError);

    expect(await lerReauth(b.sessionId)).toBeNull();
  });

  it('a escrita exige sessao ativa mesmo pelo pool privilegiado', async () => {
    const u = await novoUsuario('re35c');
    await withMigrator((m) =>
      m.query(`UPDATE identity.session SET expires_at = now() - interval '1 hour' WHERE id = $1`, [u.sessionId]),
    );

    await expect(
      reauth.reauthenticate({ userId: u.userId, sessionId: u.sessionId, password: PASSWORD, signals: signals() }),
    ).rejects.toBeInstanceOf(ReauthFailedError);

    expect(await lerReauth(u.sessionId)).toBeNull();
  });

  it('o guard exige contexto autenticado', async () => {
    await expect(guard.canActivate(contextoDe(undefined))).rejects.toMatchObject({ status: 401 });
  });
});
