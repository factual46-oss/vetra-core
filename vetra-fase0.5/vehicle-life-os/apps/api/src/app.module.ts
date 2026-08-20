import { Module } from '@nestjs/common';
import { LoggerModule } from 'nestjs-pino';
import { buildLoggerOptions } from './infra/logging/logger.options.js';
import { DatabaseModule } from './infra/db/database.module.js';
import { RedisModule } from './infra/queue/redis.module.js';
import { HealthModule } from './modules/health/health.module.js';
import { AuthModule } from './modules/auth/auth.module.js';

/**
 * Fronteira de modulos = fronteira de dominio (Doc 01, secao 5).
 * Cada fase adiciona seu modulo aqui; nenhum modulo importa o interno de outro,
 * regra verificada por lint de arquitetura no CI.
 */
@Module({
  imports: [LoggerModule.forRoot(buildLoggerOptions()), DatabaseModule, RedisModule, HealthModule, AuthModule],
})
export class AppModule {}
