import { createHmac } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { getEnv } from '../../../config/env.js';
import { AuthDatabaseService } from './auth-database.service.js';

export type AuthAction =
  | 'AUTH_REGISTERED'
  | 'AUTH_REGISTER_DUPLICATE'
  | 'AUTH_LOGIN_SUCCEEDED'
  | 'AUTH_LOGIN_FAILED'
  | 'AUTH_LOGIN_BLOCKED_ACCOUNT'
  | 'AUTH_LOGOUT'
  | 'AUTH_LOGOUT_ALL'
  | 'AUTH_SESSION_REVOKED'
  | 'AUTH_REFRESH_ROTATED'
  | 'AUTH_REFRESH_REPLAY_DETECTED'
  | 'AUTH_REFRESH_REJECTED'
  | 'AUTH_PASSWORD_REHASHED'
  | 'AUTH_TOKEN_UNKNOWN_KID'
  | 'AUTH_RATE_LIMITED'
  | 'AUTH_RATE_LIMITER_DEGRADED';

export interface AuthAuditEntry {
  action: AuthAction;
  actorUserId?: string | undefined;
  objectType?: string | undefined;
  objectId?: string | undefined;
  reason?: string | undefined;
  metadata?: Record<string, unknown> | undefined;
  ip?: string | undefined;
  requestId?: string | undefined;
}

/**
 * Eventos de autenticacao no log auditavel ja existente. NAO ha infraestrutura
 * nova: a aplicacao so tem INSERT, o selo por hash e feito por trigger no banco,
 * e nenhuma leitura e possivel por esta role (AUD-23).
 *
 * `INSERT` sem `RETURNING`: nao existe policy de SELECT, e pedir o id de volta
 * falharia -- e nao precisamos dele.
 */
@Injectable()
export class AuthAuditService {
  private readonly logger = new Logger(AuthAuditService.name);

  constructor(private readonly db: AuthDatabaseService) {}

  async record(entry: AuthAuditEntry): Promise<void> {
    const metadata = sanitizeMetadata(entry.metadata ?? {});

    try {
      await this.db.query(
        `INSERT INTO audit.log
           (actor_type, actor_user_id, action, object_type, object_id, reason, metadata, ip_hash, request_id)
         VALUES ('USER', $1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
        [
          entry.actorUserId ?? null,
          entry.action,
          entry.objectType ?? null,
          entry.objectId ?? null,
          entry.reason ?? null,
          JSON.stringify(metadata),
          entry.ip ? hashIp(entry.ip) : null,
          entry.requestId ?? null,
        ],
      );
    } catch (err) {
      // Auditoria indisponivel nao pode derrubar o login, mas tem de gritar.
      this.logger.error({ err, action: entry.action }, 'falha ao gravar evento de auditoria');
    }
  }
}

/**
 * Rede de seguranca contra vazamento por metadata. A regra de ouro e nao passar
 * segredo aqui; esta funcao existe porque "a regra de ouro" nao sobrevive a
 * pressa de um plantao. Ha teste que varre os eventos gravados procurando
 * material sensivel.
 */
const FORBIDDEN_KEYS = new Set([
  'password',
  'senha',
  'passwordhash',
  'hash',
  'token',
  'accesstoken',
  'refreshtoken',
  'refresh_token',
  'authorization',
  'cookie',
  'secret',
  'pepper',
  'totp',
  'code',
  'apikey',
]);

export function sanitizeMetadata(input: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (FORBIDDEN_KEYS.has(key.toLowerCase().replace(/[^a-z_]/g, ''))) {
      out[key] = '[REDACTED]';
      continue;
    }
    out[key] = typeof value === 'object' && value !== null ? '[OBJECT]' : value;
  }
  return out;
}

function hashIp(ip: string): Buffer {
  const key = Buffer.from(getEnv().AUDIT_IP_HASH_KEY_BASE64, 'base64');
  return createHmac('sha256', key).update(ip, 'utf8').digest();
}
