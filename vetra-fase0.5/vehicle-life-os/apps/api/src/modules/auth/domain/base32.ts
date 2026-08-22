/**
 * Base32 conforme RFC 4648.
 *
 * Alfabeto canonico da RFC, sem substituicao: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567.
 * A regra "sem caracteres ambiguos" pertence a GERACAO do segredo, nao a
 * codificacao -- alterar o alfabeto aqui produziria um segredo que nenhum
 * aplicativo autenticador consegue ler.
 *
 * CONTRATO
 *   encodeBase32(buffer)                  -> string SEM padding (padrao)
 *   encodeBase32(buffer, { padding: true }) -> string com padding canonico
 *   decodeBase32(texto)                   -> Buffer, ESTRITO
 *   normalizeBase32Input(texto)           -> normalizacao para entrada humana
 *
 * A decodificacao e estrita de proposito: aceita apenas o alfabeto da RFC e
 * padding canonico. Espacos, hifens e minusculas NAO sao removidos em silencio
 * -- quem quiser essa tolerancia chama normalizeBase32Input() explicitamente e
 * assume a decisao. Transformar entrada invalida em segredo diferente e pior
 * que recusar.
 *
 * Case: a decodificacao aceita minusculas, porque base32 e case-insensitive por
 * definicao na RFC 4648. Isso nao e substituicao de caractere invalido.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const DECODE_MAP: ReadonlyMap<string, number> = new Map(
  ALPHABET.split('').map((character, index) => [character, index]),
);

/** Restos possiveis para um bloco base32 valido. 1, 3 e 6 sao impossiveis. */
const VALID_REMAINDERS = new Set([0, 2, 4, 5, 7]);

export class InvalidBase32Error extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'InvalidBase32Error';
  }
}

export function encodeBase32(input: Buffer, options: { padding?: boolean } = {}): string {
  if (!Buffer.isBuffer(input)) throw new InvalidBase32Error('entrada deve ser Buffer');

  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) output += ALPHABET[(value << (5 - bits)) & 31];

  if (options.padding === true) {
    const remainder = output.length % 8;
    if (remainder !== 0) output += '='.repeat(8 - remainder);
  }

  return output;
}

/**
 * Decodificacao estrita.
 *
 * Recusa: caractere fora do alfabeto, padding no meio, quantidade de padding
 * incompativel com o comprimento, comprimento impossivel e bits finais nao
 * nulos (canonicidade da RFC 4648).
 */
export function decodeBase32(input: string): Buffer {
  if (typeof input !== 'string') throw new InvalidBase32Error('entrada ausente');

  // Buffer vazio faz round-trip: encodeBase32(Buffer.alloc(0)) === ''
  if (input.length === 0) return Buffer.alloc(0);

  const upper = input.toUpperCase();

  const paddingIndex = upper.indexOf('=');
  const data = paddingIndex === -1 ? upper : upper.slice(0, paddingIndex);
  const padding = paddingIndex === -1 ? '' : upper.slice(paddingIndex);

  if (padding.length > 0) {
    if (!/^=+$/.test(padding)) throw new InvalidBase32Error('padding no meio da entrada');
    if (upper.length % 8 !== 0) throw new InvalidBase32Error('entrada com padding deve ter comprimento multiplo de 8');
    const expected = (8 - (data.length % 8)) % 8;
    if (padding.length !== expected) throw new InvalidBase32Error('quantidade de padding incorreta');
  }

  if (!VALID_REMAINDERS.has(data.length % 8)) {
    throw new InvalidBase32Error(`comprimento impossivel para base32: ${data.length}`);
  }

  const bytes: number[] = [];
  let bits = 0;
  let value = 0;

  for (const character of data) {
    const index = DECODE_MAP.get(character);
    if (index === undefined) {
      throw new InvalidBase32Error(`caractere fora do alfabeto base32: ${character}`);
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  // Canonicidade: os bits que sobram precisam ser zero.
  if (bits > 0 && (value & ((1 << bits) - 1)) !== 0) {
    throw new InvalidBase32Error('bits finais nao nulos: codificacao nao canonica');
  }

  return Buffer.from(bytes);
}

/**
 * Normalizacao EXPLICITA para entrada digitada por humano: remove espacos e
 * hifens e aplica maiusculas. Nao e chamada por decodeBase32 -- quem usa,
 * decide usar.
 */
export function normalizeBase32Input(input: string): string {
  if (typeof input !== 'string') throw new InvalidBase32Error('entrada ausente');
  return input.replace(/[\s-]/g, '').toUpperCase();
}

export function isValidBase32(input: string): boolean {
  try {
    decodeBase32(input);
    return true;
  } catch {
    return false;
  }
}
