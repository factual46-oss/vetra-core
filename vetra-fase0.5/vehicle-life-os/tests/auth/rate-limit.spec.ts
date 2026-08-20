import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Redis } from 'ioredis';
import {
  RateLimitExceededError,
  RateLimitService,
  RateLimiterUnavailableError,
} from '../../apps/api/src/modules/auth/infra/rate-limit.service.js';
import { RedisService } from '../../apps/api/src/infra/queue/redis.service.js';

/**
 * D6: limites e, principalmente, comportamento quando o Redis nao responde.
 *
 * Os quatro modos de falha sao testados separadamente porque cada um chega ao
 * codigo por um caminho diferente -- e o quarto, "resposta invalida", e o mais
 * perigoso: interpretar lixo como "dentro do limite" desliga o limitador em
 * silencio, sem erro, sem log, sem ninguem perceber.
 *
 * Aqui o stub e legitimo (item 32): ele simula falha de INFRAESTRUTURA, nao
 * substitui a verificacao de seguranca do banco.
 */
describe('rate limiting', () => {
  let redis: RedisService;
  let limiter: RateLimitService;

  beforeAll(() => {
    redis = new RedisService();
    limiter = new RateLimitService(redis);
  });

  afterAll(async () => {
    await redis.onModuleDestroy();
  });

  const rule = (limit: number) => [{ key: `test:rl:${randomUUID()}`, limit, windowSeconds: 60 }];

  it('permite requisicoes ate o limite', async () => {
    const rules = rule(3);
    for (let i = 0; i < 3; i++) {
      await expect(limiter.consume(rules, 'FAIL_CLOSED')).resolves.toBeUndefined();
    }
  });

  it('recusa a partir do limite, informando quando tentar de novo', async () => {
    const rules = rule(2);
    await limiter.consume(rules, 'FAIL_CLOSED');
    await limiter.consume(rules, 'FAIL_CLOSED');

    const err = (await limiter.consume(rules, 'FAIL_CLOSED').catch((e: unknown) => e)) as RateLimitExceededError;
    expect(err).toBeInstanceOf(RateLimitExceededError);
    expect(err.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('avalia os dois eixos: estourar por conta bloqueia mesmo com IP novo', async () => {
    const account = { key: `test:rl:acc:${randomUUID()}`, limit: 1, windowSeconds: 60 };
    await limiter.consume([account, { key: `test:rl:ip:${randomUUID()}`, limit: 99, windowSeconds: 60 }], 'FAIL_CLOSED');
    await expect(
      limiter.consume([account, { key: `test:rl:ip:${randomUUID()}`, limit: 99, windowSeconds: 60 }], 'FAIL_CLOSED'),
    ).rejects.toBeInstanceOf(RateLimitExceededError);
  });

  it('reset libera o contador apos sucesso legitimo', async () => {
    const rules = rule(1);
    await limiter.consume(rules, 'FAIL_CLOSED');
    await limiter.reset(rules.map((r) => r.key));
    await expect(limiter.consume(rules, 'FAIL_CLOSED')).resolves.toBeUndefined();
  });

  // --- quatro modos de falha --------------------------------------------------

  it('1. CONNECTION REFUSED: FAIL_CLOSED recusa a requisicao', async () => {
    const broken = new Redis({ port: 1, host: '127.0.0.1', lazyConnect: true, maxRetriesPerRequest: 0,
      retryStrategy: () => null, enableOfflineQueue: false });
    const brokenLimiter = new RateLimitService({ client: broken } as unknown as RedisService);
    try {
      await expect(brokenLimiter.consume(rule(5), 'FAIL_CLOSED')).rejects.toBeInstanceOf(
        RateLimiterUnavailableError,
      );
    } finally {
      broken.disconnect();
    }
  });

  it('1b. CONNECTION REFUSED: FAIL_OPEN deixa passar, para nao derrubar o refresh', async () => {
    const broken = new Redis({ port: 1, host: '127.0.0.1', lazyConnect: true, maxRetriesPerRequest: 0,
      retryStrategy: () => null, enableOfflineQueue: false });
    const brokenLimiter = new RateLimitService({ client: broken } as unknown as RedisService);
    try {
      await expect(brokenLimiter.consume(rule(5), 'FAIL_OPEN')).resolves.toBeUndefined();
    } finally {
      broken.disconnect();
    }
  });

  it('2. TIMEOUT: operacao que nunca responde e cortada e tratada como indisponivel', async () => {
    const hanging = {
      multi: () => ({
        incr: () => ({ expire: () => ({ exec: () => new Promise(() => undefined) }) }),
      }),
    };
    const hangingLimiter = new RateLimitService({ client: hanging } as unknown as RedisService);

    const started = Date.now();
    await expect(hangingLimiter.consume(rule(5), 'FAIL_CLOSED')).rejects.toBeInstanceOf(
      RateLimiterUnavailableError,
    );
    // Corte em 50ms: o limitador nao pode virar gargalo do login.
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('3. INDISPONIBILIDADE no meio do fluxo e classificada, nao vira 500', async () => {
    const failing = {
      multi: () => ({
        incr: () => ({ expire: () => ({ exec: () => Promise.reject(new Error('connection lost')) }) }),
      }),
    };
    const failingLimiter = new RateLimitService({ client: failing } as unknown as RedisService);
    await expect(failingLimiter.consume(rule(5), 'FAIL_CLOSED')).rejects.toBeInstanceOf(
      RateLimiterUnavailableError,
    );
  });

  it('4. RESPOSTA INVALIDA e tratada como indisponivel, NUNCA como "dentro do limite"', async () => {
    // O modo de falha mais perigoso: se o servico interpretasse isto como ok,
    // o rate limiting estaria desligado sem ninguem perceber.
    for (const garbage of [null, 'ok', [], [[null, 'nao-e-numero']], [['erro']]]) {
      const weird = {
        multi: () => ({
          incr: () => ({ expire: () => ({ exec: () => Promise.resolve(garbage) }) }),
        }),
      };
      const weirdLimiter = new RateLimitService({ client: weird } as unknown as RedisService);
      await expect(weirdLimiter.consume(rule(5), 'FAIL_CLOSED')).rejects.toBeInstanceOf(
        RateLimiterUnavailableError,
      );
    }
  });

  it('erro do proprio Redis dentro da resposta e propagado como indisponibilidade', async () => {
    const errored = {
      multi: () => ({
        incr: () => ({ expire: () => ({ exec: () => Promise.resolve([[new Error('OOM'), null]]) }) }),
      }),
    };
    const erroredLimiter = new RateLimitService({ client: errored } as unknown as RedisService);
    await expect(erroredLimiter.consume(rule(5), 'FAIL_CLOSED')).rejects.toBeInstanceOf(
      RateLimiterUnavailableError,
    );
  });
});
