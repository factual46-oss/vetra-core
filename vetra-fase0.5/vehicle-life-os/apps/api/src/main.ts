import 'reflect-metadata';
import type { IncomingMessage } from 'node:http';
import type { Http2ServerRequest } from 'node:http2';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, type NestFastifyApplication } from '@nestjs/platform-fastify';
import helmet from '@fastify/helmet';
import cookie from '@fastify/cookie';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module.js';
import { ProblemDetailsFilter } from './common/problem-details.filter.js';
import { resolveRequestId } from './common/request-id.js';
import { getEnv, trustProxySetting } from './config/env.js';

/**
 * AUD-15: limite global pequeno e deliberado (gate item 20).
 * Upload de documento NAO aumenta este numero: a rota de upload sera registrada
 * na Fase 4 com @fastify/multipart, limite proprio, streaming direto para o
 * storage e validacao de magic bytes. Elevar o limite global para acomodar
 * arquivo grande ampliaria a superficie de ataque de TODA a API.
 */
const GLOBAL_BODY_LIMIT_BYTES = 1_048_576; // 1 MB

async function bootstrap(): Promise<void> {
  const env = getEnv();

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({
      /**
       * AUD-07 (ALTO, corrigido): antes era `trustProxy: true` incondicional.
       * Se a API for alcancavel diretamente, qualquer cliente forja
       * X-Forwarded-For e passa a controlar o IP visto pelo rate limiting e
       * pelo log de auditoria. Agora so confiamos nos proxies declarados.
       */
      trustProxy: trustProxySetting(env),
      bodyLimit: GLOBAL_BODY_LIMIT_BYTES,
      // AUD-10: fonte unica do id de requisicao. resolveRequestId memoiza o
      // valor na requisicao crua, entao pino e filtro de erros veem o mesmo id.
      // CI-05: parametro anotado -- o construtor do FastifyAdapter nao propaga
      // tipagem contextual, e sem a anotacao o `req` caia em implicit any.
      genReqId: (req: IncomingMessage | Http2ServerRequest): string => resolveRequestId(req),
    }),
    { bufferLogs: true },
  );

  app.useLogger(app.get(Logger));

  // Cabecalhos de seguranca (Doc 03, secao 7)
  await app.register(helmet, {
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    hsts: { maxAge: 63_072_000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  });

  // Necessario para o transporte por cookie (D5). O segredo de assinatura de
  // cookie nao e usado: os valores ja sao tokens autenticados por si.
  await app.register(cookie, {});

  const origins = env.CORS_ORIGINS.split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  app.enableCors({ origin: origins.length > 0 ? origins : false, credentials: true });

  app.setGlobalPrefix('api', { exclude: ['health/live', 'health/ready'] });
  app.enableVersioning({ type: VersioningType.URI, defaultVersion: '1' });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true, // campo desconhecido e erro, nao e ignorado
      transform: true,
    }),
  );
  app.useGlobalFilters(new ProblemDetailsFilter());
  app.enableShutdownHooks();

  await app.listen(env.API_PORT, '0.0.0.0');
}

bootstrap().catch((err: unknown) => {
  console.error('[api] falha na inicializacao:', err instanceof Error ? err.message : err);
  process.exit(1);
});
