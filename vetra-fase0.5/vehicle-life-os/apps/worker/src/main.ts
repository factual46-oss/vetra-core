import { Worker } from 'bullmq';
import type { Job } from 'bullmq';
import { Redis } from 'ioredis';
import { pino } from 'pino';
import { QUEUES, type QueueName } from './queues.js';

/*
 * Processo de workers (Fase 0: esqueleto com uma fila real).
 * Os processadores de OCR, IA e alertas entram nas Fases 5, 6 e 7 -- cada um
 * como arquivo proprio registrado aqui. Nada de processamento pesado no ciclo
 * HTTP (briefing secao 45).
 */
const logger = pino({ level: process.env.LOG_LEVEL ?? 'info', name: 'vlos-worker' });

const redisUrl = process.env.REDIS_URL;
if (!redisUrl) {
  logger.fatal('REDIS_URL nao definida');
  process.exit(1);
}

const connection = new Redis(redisUrl, { maxRetriesPerRequest: null });
const workers: Worker[] = [];

function register(name: QueueName, handler: (data: unknown) => Promise<void>, concurrency = 2): void {
  const worker = new Worker(
    name,
    async (job: Job<unknown>) => {
      const started = Date.now();
      logger.info({ queue: name, jobId: job.id, attempt: job.attemptsMade + 1 }, 'job iniciado');
      await handler(job.data);
      logger.info({ queue: name, jobId: job.id, durationMs: Date.now() - started }, 'job concluido');
    },
    { connection, concurrency },
  );

  worker.on('failed', (job: Job<unknown> | undefined, err: Error) => {
    logger.error({ queue: name, jobId: job?.id, attempt: job?.attemptsMade, err }, 'job falhou');
  });

  workers.push(worker);
}

// Fila real desde a Fase 0: verificacao diaria da cadeia de auditoria.
// Cadeia quebrada e alerta critico (Doc 04, secao 6).
register(QUEUES.AUDIT_VERIFY, async () => {
  logger.info('verificacao da cadeia de auditoria sera implementada junto ao scheduler (Fase 9)');
});

logger.info({ queues: Object.values(QUEUES) }, 'worker iniciado');

async function shutdown(signal: string): Promise<void> {
  logger.info({ signal }, 'encerrando worker');
  // close() espera os jobs em andamento terminarem antes de sair.
  await Promise.all(workers.map((w) => w.close()));
  await connection.quit();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
