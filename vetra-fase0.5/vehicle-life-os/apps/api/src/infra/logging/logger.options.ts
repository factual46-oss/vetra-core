import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Params } from 'nestjs-pino';
import type { Options } from 'pino-http';
import { getEnv } from '../../config/env.js';
import { resolveRequestId, type RequestWithId } from '../../common/request-id.js';

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

  /**
   * CI-03: o objeto e anotado como `Options` do pino-http em vez de ficar
   * inline. `Params.pinoHttp` e uma uniao (opcoes | stream | tupla), e uniao
   * nao propaga tipagem contextual: era dai que vinham os "implicitly has an
   * 'any' type" nos parametros req/res e o erro de atribuicao do logger.
   */
  const options: Options = {
    level: env.LOG_LEVEL,
    genReqId: (req: IncomingMessage, res: ServerResponse): string => {
  const id = resolveRequestId(req);
  res.setHeader('x-request-id', id);
  return id;
    },
    redact: { paths: REDACTED_PATHS, censor: '[REDACTED]' },
    // Corpo de requisicao nunca e logado por padrao.
    serializers: serializers: {
  req: (req: IncomingMessage & RequestWithId) => ({ id: req.id, method: req.method, url: req.url }),
  res: (res: ServerResponse) => ({ statusCode: res.statusCode }),
},
    autoLogging: {
      ignore: (req: IncomingMessage): boolean => req.url?.startsWith('/health') ?? false,
    },
  };

  // Atribuicao condicional em vez de `transport: cond ? {...} : undefined`:
  // passar `undefined` explicito para propriedade opcional era outro TS2375.
  if (env.NODE_ENV === 'development') {
    options.transport = { target: 'pino-pretty', options: { singleLine: true } };
  }

  return { pinoHttp: options };
}
