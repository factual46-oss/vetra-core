import { Injectable } from '@nestjs/common';
import { looksLikeOpaqueToken } from '../domain/opaque-token.js';
import { AuthAuditService } from '../infra/auth-audit.service.js';
import { AuthDatabaseService } from '../infra/auth-database.service.js';
import { JwtService } from '../infra/jwt.service.js';
import { RateLimitService } from '../infra/rate-limit.service.js';
import { RefreshTokenRepository } from '../infra/refresh-token.repository.js';
import { SessionRepository } from '../infra/session.repository.js';
import type { IssuedCredentials, RequestSignals } from './auth.service.js';

export class InvalidRefreshTokenError extends Error {
  constructor(readonly replayDetected: boolean) {
    super('refresh token invalido');
    this.name = 'InvalidRefreshTokenError';
  }
}

@Injectable()
export class RefreshService {
  constructor(
    private readonly refreshTokens: RefreshTokenRepository,
    private readonly sessions: SessionRepository,
    private readonly jwt: JwtService,
    private readonly audit: AuthAuditService,
    private readonly rateLimit: RateLimitService,
    private readonly db: AuthDatabaseService,
  ) {}

  /**
   * Rotacao com deteccao de replay.
   *
   * FAIL_OPEN no limitador (D6): quem chega aqui ja precisa possuir um refresh
   * token valido, de uso unico e verificado no banco. Falhar fechado
   * transformaria uma queda de Redis em logout global do produto em 10 minutos.
   */
  async rotate(input: { rawToken: string; signals: RequestSignals }): Promise<IssuedCredentials> {
    await this.rateLimit.consume(
      [{ key: `rl:refresh:ip:${input.signals.ip ?? 'unknown'}`, limit: 120, windowSeconds: 3600 }],
      'FAIL_OPEN',
    );

    if (!looksLikeOpaqueToken(input.rawToken)) {
      throw new InvalidRefreshTokenError(false);
    }

    // Consumo, verificacao da sessao e emissao do proximo token acontecem numa
    // unica transacao (FIX-1A-05). Auditoria e assinatura do access token ficam
    // FORA dela de proposito: sao operacoes que nao devem prender a linha do
    // refresh token nem desfazer a rotacao se falharem.
    const outcome = await this.refreshTokens.rotateAtomically(input.rawToken);

    if (outcome.status === 'REPLAY') {
      // Politica estrita: a familia inteira ja morreu dentro da transacao.
      // Consequencia de UX declarada no plano -- dois refresh legitimos em
      // paralelo derrubam a sessao. Preferimos isso a manter viva uma cadeia
      // possivelmente comprometida.
      await this.audit.record({
        action: 'AUTH_REFRESH_REPLAY_DETECTED',
        actorUserId: outcome.userId,
        objectType: 'session',
        objectId: outcome.sessionId,
        reason: 'refresh token reutilizado',
        metadata: { familyId: outcome.familyId },
        ip: input.signals.ip,
        requestId: input.signals.requestId,
      });
      throw new InvalidRefreshTokenError(true);
    }

    if (outcome.status === 'SESSION_INACTIVE') {
      await this.audit.record({
        action: 'AUTH_REFRESH_REJECTED',
        actorUserId: outcome.userId,
        reason: 'sessao revogada ou expirada',
        ip: input.signals.ip,
        requestId: input.signals.requestId,
      });
      throw new InvalidRefreshTokenError(false);
    }

    if (outcome.status === 'INVALID') {
      await this.audit.record({
        action: 'AUTH_REFRESH_REJECTED',
        reason: 'token inexistente, expirado ou revogado',
        ip: input.signals.ip,
        requestId: input.signals.requestId,
      });
      throw new InvalidRefreshTokenError(false);
    }

    const access = await this.jwt.sign({
      userId: outcome.userId,
      sessionId: outcome.sessionId,
      amr: ['pwd'],
    });

    await this.audit.record({
      action: 'AUTH_REFRESH_ROTATED',
      actorUserId: outcome.userId,
      objectType: 'session',
      objectId: outcome.sessionId,
      ip: input.signals.ip,
      requestId: input.signals.requestId,
    });

    return {
      accessToken: access.token,
      expiresInSeconds: access.expiresInSeconds,
      refreshToken: outcome.token.raw,
      sessionId: outcome.sessionId,
    };
  }
}
