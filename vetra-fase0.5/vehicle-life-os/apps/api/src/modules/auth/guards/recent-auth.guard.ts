import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { SessionRepository } from '../infra/session.repository.js';
import type { AuthenticatedRequest } from './auth.guard.js';

/**
 * Janela de reautenticacao (sudo mode). Cinco minutos.
 *
 * Cinco minutos e curto o bastante para que uma sessao roubada nao encontre a
 * janela aberta por acaso, e longo o bastante para um fluxo de configuracao de
 * MFA com tres ou quatro passos sem pedir a senha em cada um.
 */
export const REAUTH_WINDOW_SECONDS = 300;

/**
 * Exige que a senha tenha sido confirmada recentemente NESTA sessao.
 *
 * Por que existe: uma sessao roubada e uma sessao valida. Sem esta barreira, um
 * access token furtado bastaria para cadastrar ou remover o segundo fator -- e o
 * atacante manteria acesso mesmo depois de a vitima trocar a senha.
 *
 * RESPONSABILIDADE UNICA: este guard apenas LE o estado da janela.
 *   · nao verifica senha;
 *   · nao reautentica;
 *   · nao atualiza `reauthenticated_at` (renovar ao usar tornaria a janela
 *     perpetua para quem mantivesse a sessao ativa);
 *   · nao emite token algum.
 *
 * Usa-se sempre DEPOIS do AuthGuard, que popula `request.auth`. A consulta roda
 * sob RLS com o `userId` do contexto, entao um `sid` que nao pertenca ao `sub`
 * simplesmente nao retorna linha.
 */
@Injectable()
export class RecentAuthGuard implements CanActivate {
  constructor(private readonly sessions: SessionRepository) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const auth = request.auth;

    // Sem contexto autenticado o problema e de autenticacao, nao de recencia.
    if (!auth) throw new UnauthorizedException();

    const recente = await this.sessions.hasRecentReauth(
      auth.userId,
      auth.sessionId,
      REAUTH_WINDOW_SECONDS,
    );

    if (!recente) {
      // 403 e nao 401: as credenciais sao validas, falta uma prova adicional.
      // O codigo permite ao cliente saber que deve pedir a senha, em vez de
      // deslogar o usuario.
      throw new ForbiddenException({
        message: 'reautenticacao recente obrigatoria',
        code: 'REAUTH_REQUIRED',
        windowSeconds: REAUTH_WINDOW_SECONDS,
      });
    }

    return true;
  }
}
