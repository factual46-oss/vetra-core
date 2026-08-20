import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from '../../../infra/queue/redis.service.js';

/**
 * Politica quando o Redis nao responde.
 *
 * Uma regra unica seria errada. Falhar fechado no refresh derrubaria todas as
 * sessoes do produto numa queda de Redis; falhar aberto no login entregaria
 * brute force livre. Cada chamador declara a sua politica.
 */
export type UnavailablePolicy = 'FAIL_CLOSED' | 'FAIL_OPEN';

export interface RateLimitRule {
  key: string;
  limit: number;
  windowSeconds: number;
}

export class RateLimitExceededError extends Error {
  constructor(readonly retryAfterSeconds: number) {
    super('rate limit excedido');
    this.name = 'RateLimitExceededError';
  }
}

export class RateLimiterUnavailableError extends Error {
  constructor(readonly cause_: string) {
    super('limitador indisponivel');
    this.name = 'RateLimiterUnavailableError';
  }
}

/** Estouro conta como indisponivel: o limitador nao pode virar gargalo. */
const OPERATION_TIMEOUT_MS = 50;

@Injectable()
export class RateLimitService {
  private readonly logger = new Logger(RateLimitService.name);

  constructor(private readonly redis: RedisService) {}

  /**
   * Consome uma unidade de cada regra. Todas as regras sao avaliadas em conjunto
   * -- login usa dois eixos (conta e IP) porque limitar so por IP e contornavel
   * com rotacao, e limitar so por conta permite negar servico a quem e legitimo.
   */
  async consume(rules: readonly RateLimitRule[], policy: UnavailablePolicy): Promise<void> {
    try {
      for (const rule of rules) {
        const count = await this.increment(rule);
        if (count > rule.limit) {
          const ttl = await this.ttl(rule.key);
          throw new RateLimitExceededError(ttl > 0 ? ttl : rule.windowSeconds);
        }
      }
    } catch (err) {
      if (err instanceof RateLimitExceededError) throw err;

      const reason = err instanceof Error ? err.message : 'desconhecido';
      if (policy === 'FAIL_CLOSED') {
        this.logger.error({ reason }, 'limitador indisponivel: recusando requisicao');
        throw new RateLimiterUnavailableError(reason);
      }
      // Falha aberta e uma decisao consciente, e precisa deixar rastro.
      this.logger.warn({ reason }, 'limitador indisponivel: seguindo sem limite');
    }
  }

  /** Zera os contadores de um sucesso legitimo (ex.: login correto). */
  async reset(keys: readonly string[]): Promise<void> {
    try {
      await this.withTimeout(this.redis.client.del(...keys));
    } catch {
      // Nao reiniciar contador nunca e motivo para falhar a requisicao.
    }
  }

  private async increment(rule: RateLimitRule): Promise<number> {
    const raw = await this.withTimeout(
      this.redis.client
        .multi()
        .incr(rule.key)
        .expire(rule.key, rule.windowSeconds, 'NX')
        .exec(),
    );

    // Resposta inesperada tratada como indisponibilidade, NUNCA como
    // "dentro do limite": interpretar lixo como ok desliga o limitador em silencio.
    if (!Array.isArray(raw) || raw.length === 0) throw new Error('resposta invalida do redis');
    const first = raw[0];
    if (!Array.isArray(first)) throw new Error('resposta invalida do redis');
    const [error, value] = first as [Error | null, unknown];
    if (error) throw error;
    if (typeof value !== 'number') throw new Error('resposta invalida do redis');
    return value;
  }

  private async ttl(key: string): Promise<number> {
    try {
      const value = await this.withTimeout(this.redis.client.ttl(key));
      return typeof value === 'number' && value > 0 ? value : 0;
    } catch {
      return 0;
    }
  }

  private withTimeout<T>(operation: Promise<T>): Promise<T> {
    return Promise.race([
      operation,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('timeout do limitador')), OPERATION_TIMEOUT_MS).unref(),
      ),
    ]);
  }
}
