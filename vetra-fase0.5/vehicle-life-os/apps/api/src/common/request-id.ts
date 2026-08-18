import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';

/**
 * O Fastify guarda o id na sua propria Request; o pino-http recebe a
 * IncomingMessage crua, que nao tem esse campo. Sem um ponto comum, os dois
 * geram ids diferentes -- foi exatamente o defeito AUD-10.
 *
 * Aqui o id e derivado UMA vez e memoizado na requisicao crua, entao Fastify,
 * pino e o filtro de erros enxergam o mesmo valor.
 */
export type RequestWithId = IncomingMessage & { id?: string };

/** Aceita apenas ids simples: header de proxy nao vira vetor de log injection. */
const SAFE_ID = /^[\w-]{1,64}$/;

export function resolveRequestId(req: RequestWithId): string {
  if (typeof req.id === 'string' && req.id.length > 0) {
    return req.id;
  }
  const header = req.headers['x-request-id'];
  const id = typeof header === 'string' && SAFE_ID.test(header) ? header : randomUUID();
  req.id = id;
  return id;
}
