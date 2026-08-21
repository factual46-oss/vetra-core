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

export class AuthenticationError extends Error {
  constructor(message = 'credenciais invalidas') {
    super(message);
    this.name = 'AuthenticationError';
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
    await this.rateLimit.consume(
      [
        { key: `rl:reg:ip:${input.signals.ip ?? 'unknown'}`, limit: 10, windowSeconds: 3600 },
        { key: `rl:reg:email:${input.email.toLowerCase()}`, limit: 3, windowSeconds: 3600 },
      ],
      'FAIL_CLOSED',
    );

    const exists = await this.credentials.existsByEmail(input.email);
    if (exists) {
      await this.audit.record({
        action: 'AUTH_REGISTER_REJECTED_EMAIL_EXISTS',
        reason: 'email ja cadastrado',
        ip: input.signals.ip,
        requestId: input.signals.requestId,
      });
      throw new EmailAlreadyInUseError();
    }

    const passwordHash = await this.hasher.hash(input.password);
    const user = await this.credentials.createWithPassword({
      email: input.email,
      displayName: input.displayName,
      passwordHash,
    });

    await this.audit.record({
      action: 'AUTH_USER_REGISTERED',
      actorUserId: user.id,
      objectType: 'user',
      objectId: user.id,
      ip: input.signals.ip,
      requestId: input.signals.requestId,
    });

    return { userId: user.id };
  }

  async login(input: LoginInput): Promise<IssuedCredentials> {
    const normEmail = input.email.toLowerCase();
    await this.rateLimit.consume(
      [
        { key: `rl:login:ip:${input.signals.ip ?? 'unknown'}`, limit: 30, windowSeconds: 300 },
        { key: `rl:login:email:${normEmail}`, limit: 5, windowSeconds: 300 },
      ],
      'FAIL_CLOSED',
    );

    const cred = await this.credentials.findByEmailForAuth(normEmail);

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
      throw new AuthenticationError();
    }

    const session = await this.sessions.create({
      userId: cred.id,
      amr: ['pwd'],
      ip: input.signals.ip,
      userAgent: input.signals.userAgent,
    });

    const access = await this.jwt.sign({
      userId: cred.id,
      sessionId: session.id,
      amr: ['pwd'],
    });

    const refresh = await this.refreshTokens.issue({
      userId: cred.id,
      sessionId: session.id,
    });

    await this.audit.record({
      action: 'AUTH_LOGIN_SUCCESS',
      actorUserId: cred.id,
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
}
