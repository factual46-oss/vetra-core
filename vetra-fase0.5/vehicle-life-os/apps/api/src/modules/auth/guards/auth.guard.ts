import {
  type CanActivate,
  type ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { InvalidTokenError, JwtService } from '../infra/jwt.service.js';
import { SessionRepository } from '../infra/session.repository.js';
import { AuthAuditService } from '../infra/auth-audit.service.js';

export interface AuthContext {
  userId: string;
  sessionId: string;
  amr: string[];
}

export interface AuthenticatedRequest extends FastifyRequest {
  auth?: AuthContext;
}

export const ACCESS_COOKIE = 'vlos_access';

/**
 * Autenticacao de requisicao.
 *
 * Duas verificacoes, e a segunda e a que quase todo mundo esquece:
 *   1. a assinatura prova que o token foi emitido por nos;
 *   2. a consulta de sessao prova que aquele `sid` pertence aquele `sub` E que a
 *      sessao continua viva.
 *
 * A verificacao 2 roda sob RLS com `app.user_id = sub`, entao a policy da tabela
 * faz o vinculo sid<->sub de graca: um `sid` de outro usuario simplesmente nao
 * retorna linha. E ela roda em TODA requisicao -- e isso que da janela ZERO de
 * revogacao (D9). O custo e uma consulta indexada dentro da transacao que ja
 * seria aberta de qualquer forma.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly sessions: SessionRepository,
    private readonly audit: AuthAuditService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const token = extractToken(request);

    if (!token) throw new UnauthorizedException();

    let claims;
    try {
      claims = await this.jwt.verify(token);
    } catch (err) {
      if (err instanceof InvalidTokenError && err.kind === 'UNKNOWN_KID') {
        await this.audit.record({
          action: 'AUTH_TOKEN_UNKNOWN_KID',
          metadata: { kid: err.kid ?? 'ausente' },
        });
      }
      // Resposta sempre generica: nada de "assinatura invalida" versus "expirado".
      throw new UnauthorizedException();
    }

    const active = await this.sessions.isActiveForUser(claims.sid, claims.sub);
    if (!active) throw new UnauthorizedException();

    request.auth = { userId: claims.sub, sessionId: claims.sid, amr: claims.amr };
    return true;
  }
}

function extractToken(request: FastifyRequest): string | undefined {
  const header = request.headers.authorization;
  if (typeof header === 'string' && header.startsWith('Bearer ')) {
    return header.slice(7).trim() || undefined;
  }
  const cookies = (request as FastifyRequest & { cookies?: Record<string, string | undefined> }).cookies;
  return cookies?.[ACCESS_COOKIE];
}
