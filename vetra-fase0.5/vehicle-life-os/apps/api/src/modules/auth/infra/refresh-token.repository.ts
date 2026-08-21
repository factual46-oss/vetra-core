import { randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { getEnv } from '../../../config/env.js';
import { generateOpaqueToken, hashOpaqueToken } from '../domain/opaque-token.js';
import { AuthDatabaseService } from './auth-database.service.js';

export interface IssuedRefreshToken {
  /** Entregue ao cliente. Nunca persistido. */
  raw: string;
  id: string;
  familyId: string;
  expiresAt: Date;
}

export type RotateOutcome =
  | {
      status: 'OK';
      sessionId: string;
      userId: string;
      familyId: string;
      token: IssuedRefreshToken;
    }
  | { status: 'REPLAY'; sessionId: string; userId: string; familyId: string }
  | { status: 'SESSION_INACTIVE'; sessionId: string; userId: string; familyId: string }
  | { status: 'INVALID' };

export type ConsumeOutcome =
  | { status: 'OK'; tokenId: string; sessionId: string; familyId: string; userId: string }
  | { status: 'REPLAY'; familyId: string; sessionId: string; userId: string }
  | { status: 'INVALID' };

@Injectable()
export class RefreshTokenRepository {
  constructor(private readonly db: AuthDatabaseService) {}

  async issue(input: {
    sessionId: string;
    userId: string;
    familyId?: string | undefined;
    previousId?: string | undefined;
  }): Promise<IssuedRefreshToken> {
    const token = generateOpaqueToken();
    const familyId = input.familyId ?? randomUUID();
    const ttlDays = getEnv().REFRESH_TOKEN_TTL_DAYS;

    const result = await this.db.query<{ id: string; expires_at: Date }>(
      `INSERT INTO identity.refresh_token
         (session_id, family_id, user_id, token_hash, prev_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, now() + ($6 || ' days')::interval)
       RETURNING id, expires_at`,
      [input.sessionId, familyId, input.userId, token.hash, input.previousId ?? null, String(ttlDays)],
    );

    const row = result.rows[0]!;
    return { raw: token.raw, id: row.id, familyId, expiresAt: row.expires_at };
  }

  /**
   * Consumo atomico.
   *
   * O `UPDATE` condicional e o coracao da deteccao de replay E da resolucao da
   * corrida: duas requisicoes simultaneas com o mesmo token disputam a mesma
   * linha, e o PostgreSQL serializa o `UPDATE`. A segunda nao encontra linha que
   * satisfaca `used_at IS NULL` e cai no caminho de replay. Nao ha lock explicito,
   * nao ha transacao serializavel, nao ha janela.
   */
  async consume(rawToken: string): Promise<ConsumeOutcome> {
    const hash = hashOpaqueToken(rawToken);

    const consumed = await this.db.query<{
      id: string;
      session_id: string;
      family_id: string;
      user_id: string;
    }>(
      `UPDATE identity.refresh_token SET used_at = now()
        WHERE token_hash = $1
          AND used_at IS NULL
          AND revoked_at IS NULL
          AND expires_at > now()
        RETURNING id, session_id, family_id, user_id`,
      [hash],
    );

    if (consumed.rowCount === 1) {
      const row = consumed.rows[0]!;
      return {
        status: 'OK',
        tokenId: row.id,
        sessionId: row.session_id,
        familyId: row.family_id,
        userId: row.user_id,
      };
    }

    // Nao consumiu. Distinguir "ja usado" (replay) de "inexistente/expirado".
    const existing = await this.db.query<{
      session_id: string;
      family_id: string;
      user_id: string;
      used_at: Date | null;
    }>(
      `SELECT session_id, family_id, user_id, used_at
         FROM identity.refresh_token WHERE token_hash = $1`,
      [hash],
    );

    const row = existing.rows[0];
    if (row && row.used_at !== null) {
      return {
        status: 'REPLAY',
        familyId: row.family_id,
        sessionId: row.session_id,
        userId: row.user_id,
      };
    }

    return { status: 'INVALID' };
  }

  /**
   * Rotacao ATOMICA: consumo, verificacao da sessao e emissao do proximo token
   * numa unica transacao.
   *
   * FIX-1A-05. Antes cada passo era uma transacao propria, e duas requisicoes
   * simultaneas com o mesmo token faziam AMBAS perderem:
   *
   *   vencedora: UPDATE consome o token, commit
   *   perdedora: 0 linhas -> replay -> revoga a familia E A SESSAO, commit
   *   vencedora: verifica a sessao -> ja revogada pela perdedora -> falha
   *
   * Em producao isso e um app com duas telas renovando ao mesmo tempo e o
   * usuario caindo fora sem que nenhuma das duas requisicoes tenha exito.
   *
   * Dentro de uma transacao o UPDATE trava a linha: a perdedora BLOQUEIA ate a
   * vencedora commitar, e so entao enxerga `used_at` preenchido. A ordem deixa
   * de depender de sorte de escalonamento.
   */
  async rotateAtomically(rawToken: string): Promise<RotateOutcome> {
    const hash = hashOpaqueToken(rawToken);
    const ttlDays = getEnv().REFRESH_TOKEN_TTL_DAYS;

    return this.db.transaction(async (tx) => {
      const consumed = await tx.query<{
        id: string;
        session_id: string;
        family_id: string;
        user_id: string;
      }>(
        `UPDATE identity.refresh_token SET used_at = now()
          WHERE token_hash = $1
            AND used_at IS NULL
            AND revoked_at IS NULL
            AND expires_at > now()
          RETURNING id, session_id, family_id, user_id`,
        [hash],
      );

      if (consumed.rowCount !== 1) {
        const existing = await tx.query<{
          session_id: string;
          family_id: string;
          user_id: string;
          used_at: Date | null;
        }>(
          `SELECT session_id, family_id, user_id, used_at
             FROM identity.refresh_token WHERE token_hash = $1`,
          [hash],
        );

        const row = existing.rows[0];
        if (row && row.used_at !== null) {
          await tx.query(
            `UPDATE identity.refresh_token SET revoked_at = now(), revoked_reason = 'REPLAY_DETECTED'
              WHERE family_id = $1 AND revoked_at IS NULL`,
            [row.family_id],
          );
          await tx.query(
            `UPDATE identity.session SET revoked_at = now(), revoked_reason = 'REPLAY_DETECTED'
              WHERE id = $1 AND revoked_at IS NULL`,
            [row.session_id],
          );
          return {
            status: 'REPLAY',
            sessionId: row.session_id,
            familyId: row.family_id,
            userId: row.user_id,
          };
        }

        return { status: 'INVALID' };
      }

      const current = consumed.rows[0]!;

      const alive = await tx.query(
        `SELECT 1 FROM identity.session
          WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()`,
        [current.session_id],
      );

      if (alive.rowCount !== 1) {
        await tx.query(
          `UPDATE identity.refresh_token SET revoked_at = now(), revoked_reason = 'SESSION_INACTIVE'
            WHERE family_id = $1 AND revoked_at IS NULL`,
          [current.family_id],
        );
        return {
          status: 'SESSION_INACTIVE',
          sessionId: current.session_id,
          familyId: current.family_id,
          userId: current.user_id,
        };
      }

      const next = generateOpaqueToken();
      const inserted = await tx.query<{ id: string; expires_at: Date }>(
        `INSERT INTO identity.refresh_token
           (session_id, family_id, user_id, token_hash, prev_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, now() + ($6 || ' days')::interval)
         RETURNING id, expires_at`,
        [
          current.session_id,
          current.family_id,
          current.user_id,
          next.hash,
          current.id,
          String(ttlDays),
        ],
      );

      await tx.query(`UPDATE identity.session SET last_used_at = now() WHERE id = $1`, [
        current.session_id,
      ]);

      const row = inserted.rows[0]!;
      return {
        status: 'OK',
        sessionId: current.session_id,
        familyId: current.family_id,
        userId: current.user_id,
        token: { raw: next.raw, id: row.id, familyId: current.family_id, expiresAt: row.expires_at },
      };
    });
  }

  /** Reacao ao replay: a familia inteira morre, nao apenas o token reutilizado. */
  async revokeFamily(familyId: string, reason: string): Promise<number> {
    const result = await this.db.query(
      `UPDATE identity.refresh_token SET revoked_at = now(), revoked_reason = $2
        WHERE family_id = $1 AND revoked_at IS NULL`,
      [familyId, reason],
    );
    return result.rowCount ?? 0;
  }

  async revokeSessionTokens(sessionId: string, reason: string): Promise<number> {
    const result = await this.db.query(
      `UPDATE identity.refresh_token SET revoked_at = now(), revoked_reason = $2
        WHERE session_id = $1 AND revoked_at IS NULL`,
      [sessionId, reason],
    );
    return result.rowCount ?? 0;
  }
}
