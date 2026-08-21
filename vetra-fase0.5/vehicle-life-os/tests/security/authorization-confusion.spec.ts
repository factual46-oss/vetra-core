import { generateKeyPairSync } from 'node:crypto';
import { SignJWT, importPKCS8 } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from 'pg';
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
import { APP_URL, connect, expectRejection } from '../helpers/db.js';
import { cleanupUsers, requireDatabase, testSignals, uniqueEmail, withMigrator } from '../helpers/auth.js';

/**
 * CONFUSAO DE AUTORIZACAO -- 12 casos.
 *
 * A tese destes testes: validar a assinatura prova que o token foi emitido por
 * nos, e SO ISSO. Nao prova que o `sid` pertence ao `sub`, nao prova que a
 * sessao continua viva, e nao concede privilegio nenhum. Cada um desses
 * vinculos precisa de verificacao propria -- e e o caso 3 que quase todo mundo
 * esquece.
 */
requireDatabase();
const PASSWORD = 'cavalo bateria grampo';

describe('confusao de autorizacao', () => {
  let authDb: AuthDatabaseService;
  let db: DatabaseService;
  let redis: RedisService;
  let auth: AuthService;
  let sessions: SessionRepository;
  let jwt: JwtService;
  let app: Client;
  const created: string[] = [];

  let userA: string;
  let userB: string;
  let sessionA: string;
  let sessionB: string;
  let activeKeyPem: string;

  beforeAll(async () => {
    authDb = new AuthDatabaseService();
    db = new DatabaseService();
    redis = new RedisService();
    jwt = new JwtService();
    sessions = new SessionRepository(authDb, db);
    auth = new AuthService(
      new CredentialRepository(authDb),
      new PasswordHasherService(),
      sessions,
      new RefreshTokenRepository(authDb),
      jwt,
      new RateLimitService(redis),
      new AuthAuditService(authDb),
    );
    app = connect(APP_URL!);
    await app.connect();

    const keys = JSON.parse(process.env['JWT_KEYS_JSON']!) as { kid: string; privatePem: string }[];
    activeKeyPem = keys.find((k) => k.kid === 'test-active')!.privatePem;

    const a = await makeUser('confA');
    const b = await makeUser('confB');
    userA = a.userId;
    userB = b.userId;
    sessionA = a.sessionId;
    sessionB = b.sessionId;
  });

  afterAll(async () => {
    await cleanupUsers(created);
    await Promise.all([authDb.onModuleDestroy(), db.onModuleDestroy(), redis.onModuleDestroy(), app.end()]);
  });

  async function makeUser(prefix: string) {
    const email = uniqueEmail(prefix);
    const signals = { ...testSignals, ip: `198.51.100.${Math.floor(Math.random() * 250) + 1}` };
    await auth.register({ email, password: PASSWORD, displayName: prefix, signals });
    const userId = await withMigrator(async (m) => {
      const r = await m.query<{ id: string }>(`SELECT id FROM identity."user" WHERE email = $1`, [email]);
      return r.rows[0]!.id;
    });
    created.push(userId);
    const issued = await auth.login({ email, password: PASSWORD, signals });
    return { userId, sessionId: issued.sessionId, accessToken: issued.accessToken };
  }

  /** Emula o AuthGuard: verifica o token e checa a sessao sob RLS. */
  async function authenticate(token: string): Promise<{ userId: string; sessionId: string }> {
    const claims = await jwt.verify(token);
    const active = await sessions.isActiveForUser(claims.sid, claims.sub);
    if (!active) throw new Error('SESSAO_INVALIDA');
    return { userId: claims.sub, sessionId: claims.sid };
  }

  /**
   * FIX-1A-04: o token forjado nasce de um token REAL.
   *
   * As tres tentativas anteriores montaram o token a mao e falharam sempre pelo
   * mesmo motivo estrutural: faltava alguma claim que a verificacao exige (jti,
   * typ, iss, aud...), e o teste era recusado com BAD_CLAIMS ANTES de exercitar
   * o ataque que ele existe para provar. Cada rodada descobria mais um campo.
   *
   * Agora partimos de um token legitimamente emitido pelo servico e sobrescrevemos
   * apenas o que o ataque altera. O teste deixa de depender de eu adivinhar o
   * formato -- se a verificacao passar a exigir uma claim nova, o token forjado
   * ganha essa claim sozinho.
   *
   * Passar `undefined` num campo REMOVE a claim (usado no caso 12).
   */
  async function forge(overrides: Record<string, unknown>, kid = 'test-active', pem = activeKeyPem) {
    const real = await jwt.sign({ userId: userA, sessionId: sessionA, amr: ['pwd'] });
    const base = JSON.parse(Buffer.from(real.token.split('.')[1]!, 'base64url').toString()) as Record<
      string,
      unknown
    >;
    delete base['iat'];
    delete base['exp'];

    const claims: Record<string, unknown> = { ...base };
    for (const [key, value] of Object.entries(overrides)) {
      if (value === undefined) delete claims[key];
      else claims[key] = value;
    }

    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'JWT' })
      .setIssuedAt()
      .setExpirationTime('10m')
      .sign(await importPKCS8(pem, 'EdDSA'));
  }

  it('1. sub trocado com assinatura original e recusado', async () => {
    const { accessToken } = await makeUser('c1');
    const [header, payload, signature] = accessToken.split('.');
    const claims = JSON.parse(Buffer.from(payload!, 'base64url').toString()) as Record<string, unknown>;
    claims['sub'] = userB;
    const forged = `${header}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${signature}`;
    await expect(authenticate(forged)).rejects.toBeTruthy();
  });

  it('2. sub trocado e reassinado com chave estranha e recusado', async () => {
    const foreign = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const forged = await forge({ sub: userB, sid: sessionB }, 'test-active', foreign);
    await expect(authenticate(forged)).rejects.toBeTruthy();
  });

  it('3. sid de OUTRO usuario e recusado, mesmo com assinatura valida', async () => {
    // O caso central: o token e legitimamente nosso, o sub e o proprio usuario,
    // mas o sid pertence a outra pessoa. A assinatura nao diz nada sobre isso --
    // quem recusa e a policy de RLS na consulta de sessao.
    const forged = await forge({ sub: userA, sid: sessionB, amr: ['pwd'] });
    await expect(authenticate(forged)).rejects.toThrow('SESSAO_INVALIDA');
  });

  it('4. sessao revogada e recusada imediatamente (janela zero)', async () => {
    const user = await makeUser('c4');
    await expect(authenticate(user.accessToken)).resolves.toMatchObject({ userId: user.userId });

    await sessions.revoke(user.sessionId, 'TESTE');

    // Mesmo token, ainda dentro da validade de 10 minutos.
    await expect(authenticate(user.accessToken)).rejects.toThrow('SESSAO_INVALIDA');
  });

  it('5. sessao expirada e recusada', async () => {
    const user = await makeUser('c5');
    await withMigrator((m) =>
      m.query(`UPDATE identity.session SET expires_at = now() - interval '1 day' WHERE id = $1`, [user.sessionId]),
    );
    await expect(authenticate(user.accessToken)).rejects.toThrow('SESSAO_INVALIDA');
  });

  it('6. claim is_admin injetada e ignorada', async () => {
    const forged = await forge({ sub: userA, sid: sessionA, amr: ['pwd'], is_admin: true });
    const context = await authenticate(forged);

    const admin = await db.withUserContext(context.userId, async (tx) => {
      const r = await tx.query(`SELECT 1 FROM identity.admin_permission`);
      return r.rowCount;
    });
    expect(admin).toBe(0);
  });

  it('7. claim role: admin injetada nao concede privilegio', async () => {
    const forged = await forge({ sub: userA, sid: sessionA, amr: ['pwd'], role: 'admin', permissions: ['admin:users'] });
    await expect(authenticate(forged)).resolves.toMatchObject({ userId: userA });

    const err = await expectRejection(() =>
      app.query(`INSERT INTO identity.admin_permission (user_id, permission) VALUES ($1, 'admin:users')`, [userA]),
    );
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('8. amr forjada nao cria fator que nao existe', async () => {
    const forged = await forge({ sub: userA, sid: sessionA, amr: ['pwd', 'otp'] });
    const claims = await jwt.verify(forged);
    expect(claims.amr).toContain('otp');

    // A sessao no banco -- e nao a claim -- diz quais fatores foram usados.
    const stored = await withMigrator(async (m) => {
      const r = await m.query<{ amr: string[] }>(`SELECT amr FROM identity.session WHERE id = $1`, [sessionA]);
      return r.rows[0]!.amr;
    });
    expect(stored).toEqual(['pwd']);
  });

  it('9. usuario autenticado nao alcanca dado de outro usuario', async () => {
    const context = await authenticate((await makeUser('c9')).accessToken);
    const rows = await db.withUserContext(context.userId, async (tx) => {
      const r = await tx.query<{ id: string }>(`SELECT id FROM identity."user" WHERE id = $1`, [userB]);
      return r.rowCount;
    });
    expect(rows).toBe(0);
  });

  it('10. autoelevacao por escrita direta em admin_permission e negada', async () => {
    const err = await expectRejection(() =>
      app.query(`UPDATE identity.admin_permission SET permission = 'admin:grant' WHERE user_id = $1`, [userA]),
    );
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('11. a role da aplicacao nao alcanca as funcoes de credencial', async () => {
    const err = await expectRejection(() => app.query(`SELECT * FROM identity.authenticate_lookup('x@y.com')`));
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('12. token sem sid e recusado', async () => {
    const forged = await forge({ sid: undefined });
    await expect(authenticate(forged)).rejects.toBeTruthy();
  });
});
