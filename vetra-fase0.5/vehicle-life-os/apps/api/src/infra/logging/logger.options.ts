import type { Params } from 'nestjs-pino';
import { getEnv } from '../../config/env.js';
import type { IncomingMessage, ServerResponse } from 'node:http';

export const REDACTED_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-api-key"]',
  'res.headers["set-cookie"]',
  'password',
  'password_hash',
  'token',
  'refreshToken',
  'accessToken',
  'secret',
  '*.password',
  '*.secret',
  '*.token',
];

export function buildLoggerOptions(): Params {
  const env = getEnv();
  const isDev = env.NODE_ENV === 'development';

  return {
    pinoHttp: {
      level: env.LOG_LEVEL,
      transport: isDev
        ? {
            target: 'pino-pretty',
            options: {
              colorize: true,
              singleLine: true,
              translateTime: 'SYS:standard',
            },
          }
        : undefined,
      redact: {
        paths: REDACTED_PATHS,
        censor: '[REDACTED]',
      },
      serializers: {
        req(req: IncomingMessage & { id?: string; originalUrl?: string }) {
          return {
            id: req.id,
            method: req.method,
            url: req.url,
            path: req.originalUrl,
          };
        },
        res(res: ServerResponse) {
          return {
            statusCode: res.statusCode,
          };
        },
        err(err: unknown) {
          if (err instanceof Error) {
            return {
              type: err.name,
              message: err.message,
              stack: isDev ? err.stack : undefined,
            };
          }
          return err;
        },
      },
    },
  };
}

export const createLoggerOptions = buildLoggerOptions;
