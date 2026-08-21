import { Injectable } from '@nestjs/common';
import { AuthAuditService } from '../infra/auth-audit.service.js';
import { CredentialRepository } from '../infra/credential.repository.js';
import { JwtService } from '../infra/jwt.service.js';
import { PasswordHasherService } from '../infra/password-hasher.service.js';
import { RateLimitService } from '../infra/rate-limit.service.js';
import { RefreshTokenRepository } from '../infra/refresh-token.repository.js';
import { SessionRepository } from '../infra/session.repository.js';

export interface RequestSignals {
  ip?: string;
  userAgent?: string;
  requestId?: string;
}

export interface RegisterInput {
  email: string;
  password: string;
  displayName: string;
  signals: RequestSignals;
}

export interface LoginInput {
  email: string;
  password: string;
  signals: RequestSignals;
}

export interface IssuedCredentials {
  accessToken: string;
  expiresInSeconds: number;
  refreshToken: string;
  sessionId: string;
}

export class InvalidCredentialsError extends Error {
  constructor(message = 'credenciais invalidas') {
    super(message);
    this.name = 'InvalidCredentialsError';
  }
}

export class WeakPasswordError extends Error {
  constructor(message = 'senha fraca') {
    super(message);
    this.name = 'WeakPasswordError';
  }
}

export class InvalidEmailError extends Error {
  constructor(message = 'email invalido') {
    super(message);
    this.name = 'InvalidEmailError';
  }
}

export class EmailAlreadyInUseError extends Error {
  constructor() {
    super('email ja cadastrado');
    this.name = 'EmailAlreadyInUseError';
  }
}

export class RateLimitExceededError extends Error {
  constructor(readonly retryAfterSeconds: number) {
    super('muitas tentativas, tente novamente mais tarde');
    this.name = 'RateLimitExceededError';
  }
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

  async register(input: RegisterInput): Promise<{ userId: string }> {
    const normEmail = input.email.trim().toLowerCase();

    if (!normEmail || !normEmail.includes('@') || normEmail.startsWith('@') || normEmail.endsWith('@')) {
      throw new InvalidEmailError();
    }

    if (!input.password || input.password.length < 8) {
      throw new WeakPasswordError();
    }

    await this.rateLimit.consume(
      [
        { key: `rl:reg:ip:${input.signals.ip ?? 'unknown'}`, limit: 10, windowSeconds: 3600 },
        { key: `rl:reg:email:${normEmail}`, limit: 3, windowSeconds: 3600 },
      ],
      'FAIL_CLOSED',
    );

    const lookup = await this.credentials.lookupByEmail(normEmail);
    if (lookup) {
      await this.audit.record({
        action: 'AUTH_REGISTER_REJECTED',
        reason: 'email ja cadastrado',
        ip: input.signals.ip,
        requestId: input.signals.requestId,
      });
      throw new EmailAlreadyInUseError();
    }

    const passwordHash = await this.hasher.hash(input.password);
    const userId = await this.credentials.create({
      email: normEmail,
      displayName: input.displayName,
      passwordHash,
    });

    await this.audit.record({
      action: 'AUTH_REGISTERED',
      actorUserId: userId,
      objectType: 'user',
      objectId: userId,
      ip: input.signals.ip,
      requestId: input.signals.requestId,
    });

    return { userId };
  }

  async login(input: LoginInput): Promise<IssuedCredentials> {
    const normEmail = input.email.trim().toLowerCase();
    await this.rateLimit.consume(
      [
        { key: `rl:login:ip:${input.signals.ip ?? 'unknown'}`, limit: 30, windowSeconds: 300 },
        { key: `rl:login:email:${normEmail}`, limit: 5, windowSeconds: 300 },
      ],
      'FAIL_CLOSED',
    );

    const cred = await this.credentials.lookupByEmail(normEmail);

    let passwordMatches = false;
    if (cred && cred.passwordHash) {
      passwordMatches = await this.hasher.verify(cred.passwordHash, input.password);
    } else {
      await this.hasher.verifyDummy(input.password);
    }

    if (!cred || !passwordMatches) {
      await this.audit.record({
        action: 'AUTH_LOGIN_FAILED',
        reason: 'credenciais invalidas',
        metadata: { email: normEmail },
        ip: input.signals.ip,
        requestId: input.signals.requestId,
      });
      throw new InvalidCredentialsError();
    }

    const session = await this.sessions.create({
      userId: cred.userId,
      amr: ['pwd'],
      ip: input.signals.ip,
      userAgent: input.signals.userAgent,
    });

    const access = await this.jwt.sign({
      userId: cred.userId,
      sessionId: session.id,
      amr: ['pwd'],
    });

    const refresh = await this.refreshTokens.issue({
      userId: cred.userId,
      sessionId: session.id,
    });

    await this.audit.record({
      action: 'AUTH_LOGIN_SUCCEEDED',
      actorUserId: cred.userId,
      objectType: 'session',
      objectId: session.id,
      ip: input.signals.ip,
      requestId: input.signals.requestId,
    });

    return {
      accessToken: access.token,
      expiresInSeconds: access.expiresInSeconds,
      refreshToken: refresh.raw,
      sessionId: session.id,
    };
  }

  async logout(sessionId: string, userId: string, signals: RequestSignals): Promise<void> {
    await this.sessions.revoke(sessionId, 'LOGOUT');
    await this.refreshTokens.revokeSessionTokens(sessionId, 'LOGOUT');

    await this.audit.record({
      action: 'AUTH_LOGOUT',
      actorUserId: userId,
      objectType: 'session',
      objectId: sessionId,
      ip: signals.ip,
      requestId: signals.requestId,
    });
  }

  async logoutAll(userId: string, signals: RequestSignals): Promise<void> {
    await this.sessions.revokeAllForUser(userId, 'LOGOUT_ALL');

    await this.audit.record({
      action: 'AUTH_LOGOUT_ALL',
      actorUserId: userId,
      objectType: 'user',
      objectId: userId,
      ip: signals.ip,
      requestId: signals.requestId,
    });
  }
}
