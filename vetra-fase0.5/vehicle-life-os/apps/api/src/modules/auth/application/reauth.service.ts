import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../../../infra/db/database.service.js';
import { AuthAuditService } from '../infra/auth-audit.service.js';
import { AuthDatabaseService } from '../infra/auth-database.service.js';
import { CredentialRepository } from '../infra/credential.repository.js';
import { PasswordHasherService } from '../infra/password-hasher.service.js';
import { RateLimitService } from '../infra/rate-limit.service.js';
import { SessionRepository } from '../infra/session.repository.js';
import { REAUTH_WINDOW_SECONDS } from '../guards/recent-auth.guard.js';
import type { RequestSignals } from './auth.service.js';

/**
 * Erro unico para toda falha de reautenticacao.
 *
 * Nao distingue senha errada de sessao inativa. O usuario ja esta autenticado,
 * entao o risco de enumeracao e baixo -- mas manter uma resposta so evita que a
 * mensagem vire sinal sobre o estado da sessao alheia num cliente comprometido.
 */
export class ReauthFailedError extends Error {
  constructor() {
    super('nao foi possivel reautenticar');
    this.name = 'ReauthFailedError';
  }
}

@Injectable()
export class ReauthService {
  constructor(
    private readonly credentials: CredentialRepository,
    private readonly hasher: PasswordHasherService,
    private readonly sessions: SessionRepository,
    private readonly db: DatabaseService,
    private readonly authDb: AuthDatabaseService,
    private readonly rateLimit: RateLimitService,
    private readonly audit: AuthAuditService,
  ) {}

  /**
   * Confirma a senha e abre a janela de cinco minutos NA SESSAO ATUAL.
   *
   * O que este metodo deliberadamente NAO faz: nao cria sessao, nao emite
   * access token, nao emite refresh token, nao altera claims, nao altera `amr`,
   * nao altera permissao, papel nem estado de verificacao. Ele grava um
   * timestamp e nada mais.
   */
  async reauthenticate(input: {
    userId: string;
    sessionId: string;
    password: string;
    signals: RequestSignals;
  }): Promise<{ windowSeconds: number }> {
    // FAIL_CLOSED: e uma superficie de adivinhacao de senha, como o login.
    // Dois eixos -- sessao e usuario -- para que abrir varias sessoes nao
    // multiplique as tentativas disponiveis.
    await this.rateLimit.consume(
      [
        { key: `rl:reauth:session:${input.sessionId}`, limit: 5, windowSeconds: 900 },
        { key: `rl:reauth:user:${input.userId}`, limit: 10, windowSeconds: 900 },
      ],
      'FAIL_CLOSED',
    );

    // A sessao precisa estar viva ANTES de gastar um Argon2 com ela.
    // A consulta roda sob RLS: um sessionId de outro usuario nao retorna linha.
    const email = await this.resolveOwnEmail(input.userId, input.sessionId);
    if (!email) {
      await this.recordFailure(input, 'SESSION_INACTIVE');
      throw new ReauthFailedError();
    }

    const found = await this.credentials.lookup(email);
    if (!found) {
      await this.recordFailure(input, 'CREDENTIAL_MISSING');
      throw new ReauthFailedError();
    }

    const senhaConfere = await this.hasher.verify(found.passwordHash, input.password);
    if (!senhaConfere) {
      // Senha errada NAO toca em reauthenticated_at: a janela anterior, se
      // existir, permanece exatamente como estava.
      await this.recordFailure(input, 'BAD_PASSWORD');
      throw new ReauthFailedError();
    }

    // Reconfirma a sessao no proprio UPDATE: se ela foi revogada entre a
    // verificacao da senha e agora, a janela nao abre.
    const aberta = await this.openWindow(input.userId, input.sessionId);
    if (!aberta) {
      await this.recordFailure(input, 'SESSION_INACTIVE');
      throw new ReauthFailedError();
    }

    await this.audit.record({
      action: 'AUTH_REAUTH_SUCCEEDED',
      actorUserId: input.userId,
      objectType: 'session',
      objectId: input.sessionId,
      ip: input.signals.ip,
      requestId: input.signals.requestId,
    });

    return { windowSeconds: REAUTH_WINDOW_SECONDS };
  }

  /**
   * Abre a janela. PRIVADO de proposito (Bloco 3.5).
   *
   * Antes isto era um metodo publico de SessionRepository, que o AuthModule
   * exporta -- ou seja, qualquer modulo que injetasse o repositorio abriria a
   * janela sem passar por verificacao de senha. Agora a escrita so existe aqui,
   * depois do Argon2id, e nao ha caminho para chama-la sem a senha.
   *
   * Usa o pool `vlos_auth`: desde a 0016, `vlos_app` nao tem UPDATE em
   * identity.session. Uma injecao em qualquer outro modulo do produto nao
   * alcanca esta coluna.
   *
   * Como `vlos_auth` opera com policy `USING (true)`, a posse deixa de ser
   * garantida pela RLS e passa a ser verificada explicitamente no WHERE. E a
   * terceira camada: mesmo que o chamador passasse o sessionId de outra pessoa,
   * o par (id, user_id) nao casaria.
   */
  private async openWindow(userId: string, sessionId: string): Promise<boolean> {
    const result = await this.authDb.query(
      `UPDATE identity.session SET reauthenticated_at = now()
        WHERE id = $1
          AND user_id = $2
          AND revoked_at IS NULL
          AND expires_at > now()`,
      [sessionId, userId],
    );
    return result.rowCount === 1;
  }

  /**
   * O e-mail sai da propria linha do usuario, sob RLS.
   *
   * `identity.authenticate_lookup` recebe e-mail, nao user_id, e criar uma
   * funcao SECURITY DEFINER por id exigiria migration nova -- fora do escopo
   * deste bloco. Esta leitura resolve sem tocar no banco: a policy de
   * `identity."user"` ja restringe a linha ao proprio usuario.
   *
   * Devolve `undefined` quando a sessao informada nao esta viva ou nao pertence
   * ao usuario do contexto.
   */
  private async resolveOwnEmail(userId: string, sessionId: string): Promise<string | undefined> {
    return this.db.withUserContext(userId, async (tx) => {
      const sessao = await tx.query(
        `SELECT 1 FROM identity.session
          WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()`,
        [sessionId],
      );
      if (sessao.rowCount !== 1) return undefined;

      const usuario = await tx.query<{ email: string }>(`SELECT email FROM identity."user"`);
      return usuario.rows[0]?.email;
    });
  }

  private async recordFailure(
    input: { userId: string; sessionId: string; signals: RequestSignals },
    reason: string,
  ): Promise<void> {
    await this.audit.record({
      action: 'AUTH_REAUTH_FAILED',
      actorUserId: input.userId,
      objectType: 'session',
      objectId: input.sessionId,
      reason,
      ip: input.signals.ip,
      requestId: input.signals.requestId,
    });
  }
}
