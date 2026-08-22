import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * TOTP conforme RFC 6238, sobre HOTP (RFC 4226), usando apenas node:crypto.
 *
 * PARAMETROS, EXPLICITOS
 *   algoritmo : HMAC-SHA1  -- exigido pela RFC 6238 e pelo que os autenticadores
 *                             implementam. O HMAC-SHA1 nao depende da
 *                             resistencia a colisao do SHA-1.
 *   T0        : 0 segundos
 *   periodo   : 30 segundos
 *   digitos   : 6
 *   janela    : +-1 passo (aceita T-1, T, T+1) ~ 90 s de tolerancia
 *
 * FUNCOES PURAS. O timestamp e sempre parametro: nada aqui chama Date.now(),
 * para que todo teste seja deterministico e nenhum precise de sleep().
 *
 * ANTI-REPLAY NAO MORA AQUI. `last_used_step`, consumo atomico e estado
 * persistente pertencem ao servico de MFA do Bloco 5. Este arquivo nao guarda
 * estado algum.
 */

export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const TOTP_WINDOW = 1;
export const TOTP_SECRET_BYTES = 20; // 160 bits, tamanho do bloco do HMAC-SHA1

export interface TotpOptions {
  digits?: number;
  periodSeconds?: number;
  window?: number;
  t0Seconds?: number;
}

export class InvalidTotpInputError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'InvalidTotpInputError';
  }
}

interface ResolvedOptions {
  digits: number;
  periodSeconds: number;
  window: number;
  t0Seconds: number;
}

function resolveOptions(options: TotpOptions): ResolvedOptions {
  const digits = options.digits ?? TOTP_DIGITS;
  const periodSeconds = options.periodSeconds ?? TOTP_PERIOD_SECONDS;
  const window = options.window ?? TOTP_WINDOW;
  const t0Seconds = options.t0Seconds ?? 0;

  if (!Number.isInteger(digits) || digits < 6 || digits > 10) {
    throw new InvalidTotpInputError(`digits invalido: ${digits}`);
  }
  if (!Number.isInteger(periodSeconds) || periodSeconds <= 0) {
    throw new InvalidTotpInputError(`periodSeconds invalido: ${periodSeconds}`);
  }
  if (!Number.isInteger(window) || window < 0 || window > 10) {
    throw new InvalidTotpInputError(`window invalido: ${window}`);
  }
  if (!Number.isInteger(t0Seconds) || t0Seconds < 0) {
    throw new InvalidTotpInputError(`t0Seconds invalido: ${t0Seconds}`);
  }

  return { digits, periodSeconds, window, t0Seconds };
}

function assertSecret(secret: Buffer): void {
  if (!Buffer.isBuffer(secret) || secret.length === 0) {
    throw new InvalidTotpInputError('segredo ausente ou vazio');
  }
}

function assertTimestamp(timestampMs: number): void {
  if (!Number.isFinite(timestampMs) || !Number.isInteger(timestampMs) || timestampMs < 0) {
    throw new InvalidTotpInputError(`timestampMs invalido: ${timestampMs}`);
  }
}

/** Segredo novo, sempre de CSPRNG. */
export function generateTotpSecret(bytes: number = TOTP_SECRET_BYTES): Buffer {
  if (!Number.isInteger(bytes) || bytes < 16) {
    throw new InvalidTotpInputError(`tamanho de segredo invalido: ${bytes}`);
  }
  return randomBytes(bytes);
}

export function counterForTimestamp(timestampMs: number, options: TotpOptions = {}): number {
  assertTimestamp(timestampMs);
  const { periodSeconds, t0Seconds } = resolveOptions(options);
  return Math.floor((Math.floor(timestampMs / 1000) - t0Seconds) / periodSeconds);
}

/**
 * HOTP -- RFC 4226, secao 5.3 (truncamento dinamico).
 *
 * O padStart nao e cosmetico: cerca de 10% dos codigos comecam com zero, e
 * tratar o resultado como numero produz um codigo mais curto que nunca confere.
 * E o defeito classico de implementacao de TOTP.
 */
export function hotp(secret: Buffer, counter: number, digits: number = TOTP_DIGITS): string {
  assertSecret(secret);
  if (!Number.isInteger(counter) || counter < 0) {
    throw new InvalidTotpInputError(`counter invalido: ${counter}`);
  }

  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(BigInt(counter));

  const digest = createHmac('sha1', secret).update(counterBytes).digest();

  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);

  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function generateTotp(secret: Buffer, timestampMs: number, options: TotpOptions = {}): string {
  assertSecret(secret);
  const resolved = resolveOptions(options);
  return hotp(secret, counterForTimestamp(timestampMs, options), resolved.digits);
}

/**
 * Verificacao dentro da janela.
 *
 * O codigo NUNCA e convertido para numero: a comparacao e feita sobre os bytes
 * da string, em tempo constante. Converter perderia o zero a esquerda e
 * transformaria '000001' em 1.
 */
export function verifyTotp(
  secret: Buffer,
  code: string,
  timestampMs: number,
  options: TotpOptions = {},
): boolean {
  return findMatchingStep(secret, code, timestampMs, options) !== null;
}

/**
 * Igual a verifyTotp, mas devolve QUAL passo casou.
 *
 * Existe porque o anti-replay do Bloco 5 precisa desse valor para o UPDATE
 * condicional em `last_used_step`. Sem ele, o servico seria obrigado ao padrao
 * SELECT -> verifica -> UPDATE, que a decisao D21 proibe.
 *
 * Esta funcao continua pura: nao guarda estado, nao consulta banco, nao decide
 * politica -- apenas informa o passo.
 */
export function findMatchingStep(
  secret: Buffer,
  code: string,
  timestampMs: number,
  options: TotpOptions = {},
): number | null {
  assertSecret(secret);
  const { digits, window } = resolveOptions(options);

  if (typeof code !== 'string') return null;
  if (code.length !== digits || !/^\d+$/.test(code)) return null;

  const current = counterForTimestamp(timestampMs, options);
  const expected = Buffer.from(code, 'utf8');

  let matched: number | null = null;

  // Percorre a janela inteira mesmo apos encontrar: evita que o tempo de
  // resposta revele qual passo casou.
  for (let drift = -window; drift <= window; drift++) {
    const step = current + drift;
    if (step < 0) continue;

    const generated = Buffer.from(hotp(secret, step, digits), 'utf8');
    if (generated.length === expected.length && timingSafeEqual(generated, expected) && matched === null) {
      matched = step;
    }
  }

  return matched;
}
