import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Refresh tokens e demais segredos opacos.
 *
 * POR QUE SHA-256 E NAO ARGON2 (a escolha parece contradizer o rigor aplicado a
 * senha, entao vale explicitar): Argon2 protege segredos de BAIXA entropia, onde
 * o atacante enumera o espaco de busca. 256 bits aleatorios nao sao enumeraveis.
 * Um hash lento aqui so adicionaria latencia e CPU em toda renovacao, sem ganho.
 * O que protege o refresh token e entropia, rotacao e deteccao de replay.
 */

const TOKEN_BYTES = 32; // 256 bits

export interface OpaqueToken {
  /** Valor entregue ao cliente. Nunca persistido. */
  raw: string;
  /** SHA-256 do valor bruto. E o que vai para o banco. */
  hash: Buffer;
}

export function generateOpaqueToken(): OpaqueToken {
  const raw = randomBytes(TOKEN_BYTES).toString('base64url');
  return { raw, hash: hashOpaqueToken(raw) };
}

export function hashOpaqueToken(raw: string): Buffer {
  return createHash('sha256').update(raw, 'utf8').digest();
}

/** Comparacao em tempo constante, para uso fora de consulta indexada. */
export function opaqueTokenMatches(raw: string, expected: Buffer): boolean {
  const actual = hashOpaqueToken(raw);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/** Formato aceito na entrada: base64url de 32 bytes. */
export function looksLikeOpaqueToken(raw: unknown): raw is string {
  return typeof raw === 'string' && /^[A-Za-z0-9_-]{43}$/.test(raw);
}
