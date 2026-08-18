import { randomUUID } from 'node:crypto';

/**
 * Contrato estrutural mínimo, em vez de amarrar a um tipo concreto do Node.
 *
 * CI-07: o Fastify tipa genReqId como `(req: IncomingMessage | Http2ServerRequest)`.
 * Uma função que aceita só IncomingMessage não é atribuível a essa assinatura
 * (contravariância de parâmetro). Descrevendo apenas o que a função realmente
 * usa — headers e id — tanto IncomingMessage quanto Http2ServerRequest passam
 * a satisfazer o contrato sem cast, e a mesma função serve ao Fastify e ao pino.
 */
export interface RequestWithId {
  id?: string;
  headers: { [key: string]: string | string[] | undefined };
}

/** Aceita apenas ids simples: header de proxy não vira vetor de log injection. */
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
