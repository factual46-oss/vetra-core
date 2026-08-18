import { Injectable, Logger, type OnModuleDestroy } from '@nestjs/common';
import Redis from 'ioredis';
import { getEnv } from '../../config/env.js';

/**
 * Conexao Redis compartilhada (filas BullMQ na Fase 5, rate limit na Fase 1).
 * maxRetriesPerRequest: null e exigencia do BullMQ.
 */
@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  readonly client: Redis;

  constructor() {
    this.client = new Redis(getEnv().REDIS_URL, { maxRetriesPerRequest: null, lazyConnect: false });
    this.client.on('error', (err) => this.logger.error({ err }, 'erro no redis'));
  }

  async ping(): Promise<void> {
    const reply = await this.client.ping();
    if (reply !== 'PONG') throw new Error(`resposta inesperada do redis: ${reply}`);
  }

  async onModuleDestroy(): Promise<void> {
    await this.client.quit();
  }
}
