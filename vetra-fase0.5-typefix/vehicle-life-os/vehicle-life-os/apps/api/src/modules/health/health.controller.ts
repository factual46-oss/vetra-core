import { Controller, Get, HttpCode, HttpStatus, Logger, Res } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { DatabaseService } from '../../infra/db/database.service.js';
import { RedisService } from '../../infra/queue/redis.service.js';

type CheckState = 'ok' | 'error';
interface ReadyReport {
  status: CheckState;
  checks: Record<string, { status: CheckState; latencyMs: number }>;
}

const CACHE_TTL_MS = 3_000;

/**
 * Doc 04, secao 6:
 *   /health/live  -> o processo respira. Usado pelo Docker.
 *   /health/ready -> dependencias respondem. Usado pelo proxy.
 *
 * AUD-12 (ALTO, corrigido): a versao anterior devolvia err.message ao cliente.
 * Erros de conexao do Postgres carregam host, porta, usuario e as vezes o motivo
 * exato da recusa de autenticacao -- reconhecimento gratuito para um atacante
 * num endpoint sem autenticacao. Agora o detalhe vai para o log; o cliente
 * recebe apenas ok/error.
 *
 * AUD-14: resultado cacheado por alguns segundos. Sem isso, um endpoint publico
 * e sem custo de autenticacao dispara uma consulta ao banco por requisicao.
 */
@Controller('health')
export class HealthController {
  private readonly logger = new Logger(HealthController.name);
  private cache?: { at: number; report: ReadyReport };

  constructor(
    private readonly db: DatabaseService,
    private readonly redis: RedisService,
  ) {}

  @Get('live')
  @HttpCode(HttpStatus.OK)
  live(): { status: 'ok' } {
    return { status: 'ok' };
  }

  @Get('ready')
  async ready(@Res({ passthrough: true }) reply: FastifyReply): Promise<ReadyReport> {
    const now = Date.now();
    if (this.cache && now - this.cache.at < CACHE_TTL_MS) {
      reply.status(this.cache.report.status === 'ok' ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE);
      return this.cache.report;
    }

    const checks: ReadyReport['checks'] = {};

    for (const [name, probe] of [
      ['database', () => this.db.ping()],
      ['redis', () => this.redis.ping()],
    ] as const) {
      const started = Date.now();
      try {
        await probe();
        checks[name] = { status: 'ok', latencyMs: Date.now() - started };
      } catch (err) {
        // detalhe apenas no log, nunca na resposta
        this.logger.error({ err, dependency: name }, 'dependencia indisponivel');
        checks[name] = { status: 'error', latencyMs: Date.now() - started };
      }
    }

    const status: CheckState = Object.values(checks).every((c) => c.status === 'ok') ? 'ok' : 'error';
    const report: ReadyReport = { status, checks };
    this.cache = { at: now, report };

    reply.status(status === 'ok' ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE);
    return report;
  }
}
