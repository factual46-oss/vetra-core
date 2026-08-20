/**
 * Conjunto de chaves de assinatura (D3).
 *
 * Ciclo de vida em quatro tempos:
 *   T0  gerar par novo, entra como `next`      -> so verifica
 *   T1  promover a `active`, anterior vira `retiring`
 *   T2  periodo de graca de 1 hora             -> `retiring` ainda verifica
 *   T3  remover `retiring` do conjunto
 *
 * A graca existe porque, sem ela, a promocao invalidaria instantaneamente todo
 * token ja assinado: ate 10 minutos de 401 em massa. Uma hora e folga confortavel
 * sobre o TTL sem manter chave velha viva por tempo relevante.
 */

export type KeyStatus = 'active' | 'next' | 'retiring';

export interface JwtKey {
  kid: string;
  status: KeyStatus;
  privatePem: string;
  publicPem: string;
}

export class KeySetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeySetError';
  }
}

const MIN_PEM_LENGTH = 100;
const KID_SHAPE = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * Valida o conjunto. Em producao exige exatamente uma chave `active`; fora dela
 * o conjunto pode estar vazio, para que o ambiente de desenvolvimento suba sem
 * chave configurada ate o momento em que alguem tentar assinar.
 */
export function parseKeySet(keys: readonly JwtKey[], requireActive: boolean): JwtKey[] {
  if (!Array.isArray(keys)) throw new KeySetError('conjunto de chaves invalido');

  const seen = new Set<string>();
  for (const key of keys) {
    if (!KID_SHAPE.test(key.kid)) throw new KeySetError(`kid invalido: ${String(key.kid)}`);
    if (seen.has(key.kid)) throw new KeySetError(`kid duplicado: ${key.kid}`);
    seen.add(key.kid);

    if (!['active', 'next', 'retiring'].includes(key.status)) {
      throw new KeySetError(`status invalido para ${key.kid}`);
    }
    if (!key.privatePem.includes('PRIVATE KEY') || key.privatePem.length < MIN_PEM_LENGTH) {
      throw new KeySetError(`chave privada invalida em ${key.kid}`);
    }
    if (!key.publicPem.includes('PUBLIC KEY') || key.publicPem.length < MIN_PEM_LENGTH) {
      throw new KeySetError(`chave publica invalida em ${key.kid}`);
    }
  }

  const active = keys.filter((k) => k.status === 'active');
  if (requireActive && active.length !== 1) {
    throw new KeySetError(`esperada exatamente uma chave active, encontradas ${active.length}`);
  }

  return [...keys];
}

export function selectSigningKey(keys: readonly JwtKey[]): JwtKey {
  const active = keys.find((k) => k.status === 'active');
  if (!active) throw new KeySetError('nenhuma chave active para assinar');
  return active;
}

/** Verificacao aceita qualquer status: `next` e `retiring` existem para isso. */
export function resolveVerificationKey(keys: readonly JwtKey[], kid: unknown): JwtKey | undefined {
  if (typeof kid !== 'string') return undefined;
  return keys.find((k) => k.kid === kid);
}
