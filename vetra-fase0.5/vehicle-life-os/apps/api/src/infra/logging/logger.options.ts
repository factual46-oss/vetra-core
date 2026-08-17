import type { Params } from 'nestjs-pino';
import { getEnv } from '../../config/env.js';

/**
 * Briefing secao 87 / Doc 03 secao 9:
 * a redacao e configuracao do logger, nao convencao de quem escreve o log.
 * Nao ha caminho em que um destes campos chegue ao disco em claro.
 */
export const REDACTED_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-api-key"]',
  'res.headers["set-cookie"]',
  'password',
  '*.password',
  'passwordConfirmation',
  'token',
  '*.token',
  'refreshToken',
  'accessToken',
  'cpf',
  '*.cpf',
  'vin',
  '*.vin',
  'plate',
  '*.plate',
  'renavam',
  '*.renavam',
  'secret',
  '*.secret',
  'apiKey',
  '*.apiKey',
  'connectionString',
  '*.connectionString',
];

/**
 * AUD-06: construida sob demanda, nao no import.
 * AUD-10: o id da requisicao vem do Fastify (fonte unica). Antes havia dois
 * geradores concorrentes -- o do adapter e o do pino-http -- e o traceId que
 * o cliente recebia no erro nao era o mesmo que aparecia no log. Rastreabilidade
 * quebrada e exatamente o tipo de defeito que so aparece durante um incidente.
 */
export function buildLoggerOptions(): Params {
  const env = getEnv();
  return {
    pinoHttp: {
      level: env.LOG_LEVEL,
      genReqId: (req, res) => {
        const id = String(req.id);
        res.setHeader('x-request-id', id);
        return id;
      },
      redact: { paths: REDACTED_PATHS, censor: '[REDACTED]' },
      serializers: {
        req: (req) => ({ id: req.id, method: req.method, url: req.url }),
        res: (res) => ({ statusCode: res.statusCode }),
      },
      autoLogging: { ignore: (req) => req.url?.startsWith('/health') ?? false },
      transport:
        env.NODE_ENV === 'development'
          ? { target: 'pino-pretty', options: { singleLine: true } }
          : undefined,
    },
  };
}
