import { Injectable } from '@nestjs/common';
import { InvalidEmailError, normalizeEmail } from '../domain/email.js';
import { checkPassword } from '../domain/password-policy.js';
import { AuthAuditService } from '../infra/auth-audit.service.js';
import { CredentialRepository, EmailAlreadyRegisteredError } from '../infra/credential.repository.js';
import { PasswordHasherService } from '../infra/password-hasher.service.js';
import { RefreshTokenRepository } from '../infra/refresh-token.repository.js';
import { SessionRepository } from '../infra/session.repository.js';
import { JwtService } from '../infra/jwt.service.js';
import { RateLimitService } from '../infra/rate-limit.service.js';

/**
 * Erro unico para toda falha de login.
 *
 * Nao distingue "conta inexistente", "senha errada" nem "conta bloqueada". A
 * diferenca util para o usuario legitimo e nenhuma; a diferenca util para quem
 * enumera contas e enorme.
 */
export class InvalidCredentialsError extends Error {
  constructor() {
    super('credenciais invalidas');
    this.name = 'InvalidCredentialsError';
  }
}

export class WeakPasswordError extends Error {
  constructor(readonly rejection: string) {
    super('senha nao atende a politica');
    this.name = 'WeakPasswordError';
  }
}

export interface RequestSignals {
  ip?: string | undefined;
  userAgent?: string | undefined;
  requestId?: string | undefined;
}

export interface IssuedCredentials {
  accessToken: string;
  expiresInSeconds: number;
  refreshToken: string;
  sessionId: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly credentials: CredentialRepository,
    private readonly hasher: PasswordHasherService,
    private readonly sessions: SessionRepository,
    private readonly refreshTokens: RefreshTokenRepository,
    private readonly jwt: JwtService,
    private readonly rateLimit: RateLimitService,
    private readonly audit: AuthAuditService,
  ) {}

  /**
   * Cadastro.
   *
   * Resposta identica para e-mail novo e e-mail ja cadastrado (item 9). Sem isso,
   * o cadastro vira oraculo de existencia -- basta tentar cadastrar para saber
   * quem tem conta. O duplicado e apenas auditado; a conclusao do fluxo depende
   * da verificacao de e-mail (Fase 1B).
   */
  async register(input: {
    email: string;
    password: string;
    displayName: string;
    signals: RequestSignals;
  }): Promise<void> {
    await this.rateLimit.consume(
      [{ key: `rl:register:ip:${input.signals.ip ?? 'unknown'}`, limit: 5, windowSeconds: 3600 }],
      'FAIL_CLOSED',
    );

    let email: string;
    try {
      email = normalizeEmail(input.email);
    } catch (err) {
      if (err instanceof InvalidEmailError) throw err;
      throw err;
    }

    const check = checkPassword(input.password);
    if (!check.ok) throw new WeakPasswordError(check.rejection ?? 'INVALID');

    const hashed = await this.hasher.hash(input.password);

    try {
      const userId = await this.credentials.register({
        email,
        displayName: input.displayName.trim().slice(0, 120),
        passwordHash: hashed.hash,
        params: hashed.params,
      });
      await this.audit.record({
        action: 'AUTH_REGISTERED',
        actorUserId: userId,
        objectType: 'user',
        objectId: userId,
        ip: input.signals.ip,
        requestId: input.signals.requestId,
      });
    } catch (err) {
      if (err instanceof EmailAlreadyRegisteredError) {
        // Silencio para o cliente, registro para nos.
        await this.audit.record({
          action: 'AUTH_REGISTER_DUPLICATE',
          ip: input.signals.ip,
          requestId: input.signals.requestId,
        });
        return;
      }
      throw err;
    }
  }

  async login(input: {
    email: string;
    password: string;
    signals: RequestSignals;
  }): Promise<IssuedCredentials> {
    const emailKey = safeKey(input.email);
    const rules = [
      { key: `rl:login:email:${emailKey}`, limit: 5, windowSeconds: 900 },
      { key: `rl:login:ip:${input.signals.ip ?? 'unknown'}`, limit: 20, windowSeconds: 900 },
    ];
    // FAIL_CLOSED: o limitador e a unica defesa contra forca bruta de senha.
    await this.rateLimit.consume(rules, 'FAIL_CLOSED');

    let email: string;
    try {
      email = normalizeEmail(input.email);
    } catch {
      // E-mail malformado nao ganha resposta diferente de senha errada.
      await this.hasher.verifyDummy(input.password);
      throw new InvalidCredentialsError();
    }

    const found = await this.credentials.lookup(email);

    if (!found) {
      // Verificacao de descarte: nao promete timing perfeito, remove o sinal obvio.
      await this.hasher.verifyDummy(input.password);
      await this.audit.record({
        action: 'AUTH_LOGIN_FAILED',
        reason: 'UNKNOWN_ACCOUNT',
        ip: input.signals.ip,
        requestId: input.signals.requestId,
      });
      throw new InvalidCredentialsError();
    }

    const passwordOk = await this.hasher.verify(found.passwordHash, input.password);

    if (!passwordOk) {
      await this.audit.record({
        action: 'AUTH_LOGIN_FAILED',
        actorUserId: found.userId,
        reason: 'BAD_PASSWORD',
        ip: input.signals.ip,
        requestId: input.signals.requestId,
      });
      throw new InvalidCredentialsError();
    }

    if (found.isBlocked) {
      // A senha ja foi verificada: o custo em tempo e o mesmo do caminho feliz.
      await this.audit.record({
        action: 'AUTH_LOGIN_BLOCKED_ACCOUNT',
        actorUserId: found.userId,
        ip: input.signals.ip,
        requestId: input.signals.requestId,
      });
      throw new InvalidCredentialsError();
    }

    // Endurecimento de parametros sem invalidar senha alguma.
    if (this.hasher.needsRehash(found.params)) {
      const rehashed = await this.hasher.hash(input.password);
      await this.credentials.setPassword({
        userId: found.userId,
        passwordHash: rehashed.hash,
        params: rehashed.params,
        rehashOnly: true,
      });
      await this.audit.record({ action: 'AUTH_PASSWORD_REHASHED', actorUserId: found.userId });
    }

    const issued = await this.issueSession(found.userId, ['pwd'], input.signals);

    await this.rateLimit.reset(rules.map((r) => r.key));
    await this.audit.record({
      action: 'AUTH_LOGIN_SUCCEEDED',
      actorUserId: found.userId,
      objectType: 'session',
      objectId: issued.sessionId,
      ip: input.signals.ip,
      requestId: input.signals.requestId,
    });

    return issued;
  }

  async issueSession(
    userId: string,
    amr: string[],
    signals: RequestSignals,
  ): Promise<IssuedCredentials> {
    const session = await this.sessions.create({
      userId,
      amr,
      ip: signals.ip,
      userAgent: signals.userAgent,
    });
    const refresh = await this.refreshTokens.issue({ sessionId: session.id, userId });
    const access = await this.jwt.sign({ userId, sessionId: session.id, amr });

    return {
      accessToken: access.token,
      expiresInSeconds: access.expiresInSeconds,
      refreshToken: refresh.raw,
      sessionId: session.id,
    };
  }

  async logout(input: { userId: string; sessionId: string; signals: RequestSignals }): Promise<void> {
    await this.sessions.revoke(input.sessionId, 'LOGOUT');
    await this.refreshTokens.revokeSessionTokens(input.sessionId, 'LOGOUT');
    await this.audit.record({
      action: 'AUTH_LOGOUT',
      actorUserId: input.userId,
      objectType: 'session',
      objectId: input.sessionId,
      ip: input.signals.ip,
      requestId: input.signals.requestId,
    });
  }

  async logoutAll(input: { userId: string; signals: RequestSignals }): Promise<number> {
    const sessions = await this.sessions.listOwn(input.userId);
    for (const session of sessions) {
      await this.refreshTokens.revokeSessionTokens(session.id, 'LOGOUT_ALL');
    }
    const revoked = await this.sessions.revokeAllForUser(input.userId, 'LOGOUT_ALL');
    await this.audit.record({
      action: 'AUTH_LOGOUT_ALL',
      actorUserId: input.userId,
      metadata: { revokedSessions: revoked },
      ip: input.signals.ip,
      requestId: input.signals.requestId,
    });
    return revoked;
  }
}

/** Chave de rate limit derivada do e-mail sem grava-lo em claro no Redis. */
function safeKey(email: string): string {
  return Buffer.from(email.trim().toLowerCase(), 'utf8').toString('base64url').slice(0, 64);
}
