import { createHmac } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { getEnv } from '../../../config/env.js';
import { DatabaseService } from '../../../infra/db/database.service.js';
import { AuthDatabaseService } from './auth-database.service.js';

export interface SessionRecord {
  id: string;
  userId: string;
  amr: string[];
  expiresAt: Date;
  revokedAt: Date | null;
}

/**
 * Privacidade (item 35): guardamos HMAC de IP e user agent, nunca o valor em
 * claro. Servem para o usuario reconhecer sessao suspeita e para correlacionar
 * abuso; nao servem, e nao devem servir, para perfilamento.
 */
function hashSignal(value: string | undefined): Buffer | null {
  if (!value) return null;
  const key = Buffer.from(getEnv().AUDIT_IP_HASH_KEY_BASE64, 'base64');
  return createHmac('sha256', key).update(value, 'utf8').digest();
}

@Injectable()
export class SessionRepository {
  constructor(
    private readonly authDb: AuthDatabaseService,
    private readonly db: DatabaseService,
  ) {}

  async create(input: {
    userId: string;
    amr: string[];
    ip?: string | undefined;
    userAgent?: string | undefined;
  }): Promise<SessionRecord> {
    const ttlDays = getEnv().SESSION_TTL_DAYS;
    const result = await this.authDb.query<{
      id: string;
      user_id: string;
      amr: string[];
      expires_at: Date;
      revoked_at: Date | null;
    }>(
      `INSERT INTO identity.session (user_id, amr, expires_at, ip_hash, user_agent_hash)
       VALUES ($1, $2, now() + ($3 || ' days')::interval, $4, $5)
       RETURNING id, user_id, amr, expires_at, revoked_at`,
      [input.userId, input.amr, String(ttlDays), hashSignal(input.ip), hashSignal(input.userAgent)],
    );

    const row = result.rows[0]!;
    return { id: row.id, userId: row.user_id, amr: row.amr, expiresAt: row.expires_at, revokedAt: null };
  }

  /**
   * Verificacao de estado por requisicao (D9), executada como `vlos_app` sob
   * RLS. A policy da tabela exige `user_id = ops.current_user_id()`, entao esta
   * consulta faz DUAS coisas de uma vez: confirma que a sessao esta viva e
   * confirma que o `sid` pertence ao `sub` do token -- o vinculo que assinatura
   * valida nao prova.
   */
  async isActiveForUser(sessionId: string, userId: string): Promise<boolean> {
    return this.db.withUserContext(userId, async (tx) => {
      const result = await tx.query(
        `SELECT 1 FROM identity.session
          WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()`,
        [sessionId],
      );
      return result.rowCount === 1;
    });
  }

  async touch(sessionId: string): Promise<void> {
    await this.authDb.query(`UPDATE identity.session SET last_used_at = now() WHERE id = $1`, [
      sessionId,
    ]);
  }

  async revoke(sessionId: string, reason: string): Promise<void> {
    await this.authDb.query(
      `UPDATE identity.session SET revoked_at = now(), revoked_reason = $2
        WHERE id = $1 AND revoked_at IS NULL`,
      [sessionId, reason],
    );
  }

  async revokeAllForUser(userId: string, reason: string): Promise<number> {
    const result = await this.authDb.query(
      `UPDATE identity.session SET revoked_at = now(), revoked_reason = $2
        WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId, reason],
    );
    return result.rowCount ?? 0;
  }

  /** Lista as proprias sessoes, sob RLS. */
  async listOwn(userId: string): Promise<SessionRecord[]> {
    return this.db.withUserContext(userId, async (tx) => {
      const result = await tx.query<{
        id: string;
        user_id: string;
        amr: string[];
        expires_at: Date;
        revoked_at: Date | null;
      }>(
        `SELECT id, user_id, amr, expires_at, revoked_at
           FROM identity.session
          WHERE revoked_at IS NULL AND expires_at > now()
          ORDER BY created_at DESC`,
      );
      return result.rows.map((r) => ({
        id: r.id,
        userId: r.user_id,
        amr: r.amr,
        expiresAt: r.expires_at,
        revokedAt: r.revoked_at,
      }));
    });
  }
}
