import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { Logger } from 'nestjs-pino';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import { AppModule } from './app.module.js';
import { getEnv } from './config/env.js';
import type { IncomingMessage } from 'node:http';
import type { Http2ServerRequest } from 'node:http2';

export async function bootstrap(): Promise<NestFastifyApplication> {
  const env = getEnv();

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({
      logger: false,
      genReqId: (req: IncomingMessage | Http2ServerRequest) => {
        const headerId = req.headers['x-request-id'];
        if (typeof headerId === 'string' && headerId.length > 0) {
          return headerId;
        }
        return crypto.randomUUID();
      },
    }),
    { bufferLogs: true },
  );

  const logger = app.get(Logger);
  app.useLogger(logger);

  await app.register(helmet, {
    contentSecurityPolicy: env.NODE_ENV === 'production',
  });

  await app.register(cors, {
    origin: (origin: string | undefined, cb: (err: Error | null, allow?: boolean) => void) => {
      if (!origin || env.CORS_ORIGINS.includes(origin)) {
        cb(null, true);
        return;
      }
      cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
  });

  await app.register(cookie, {
    secret: env.COOKIE_SECRET,
    parseOptions: {},
  });

  await app.listen(env.PORT, env.HOST);
  return app;
}

if (process.env.NODE_ENV !== 'test') {
  void bootstrap();
}
