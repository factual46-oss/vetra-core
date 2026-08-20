import { type CanActivate, type ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { timingSafeEqual } from 'node:crypto';
import type { FastifyRequest } from 'fastify';

export const CSRF_COOKIE = 'vlos_csrf';
export const CSRF_HEADER = 'x-csrf-token';

/**
 * CSRF por double-submit, aplicado APENAS quando a requisicao se autentica por
 * cookie.
 *
 * O vetor existe so no modo cookie, porque so ele e enviado automaticamente pelo
 * navegador. No modo Bearer nada anexa o cabecalho sem o JavaScript da propria
 * aplicacao, e o guard sai do caminho.
 *
 * SameSite=Lax sozinho nao basta: nao cobre navegador antigo nem subdominio
 * comprometido. Por isso os dois mecanismos, nao um.
 */
@Injectable()
export class CsrfGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<
      FastifyRequest & { cookies?: Record<string, string | undefined> }
    >();

    const usesBearer =
      typeof request.headers.authorization === 'string' &&
      request.headers.authorization.startsWith('Bearer ');
    if (usesBearer) return true;

    const method = request.method.toUpperCase();
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return true;

    const cookieValue = request.cookies?.[CSRF_COOKIE];
    const headerValue = request.headers[CSRF_HEADER];

    if (typeof cookieValue !== 'string' || typeof headerValue !== 'string') {
      throw new ForbiddenException();
    }

    const a = Buffer.from(cookieValue, 'utf8');
    const b = Buffer.from(headerValue, 'utf8');
    if (a.length !== b.length || !timingSafeEqual(a, b)) throw new ForbiddenException();

    return true;
  }
}
