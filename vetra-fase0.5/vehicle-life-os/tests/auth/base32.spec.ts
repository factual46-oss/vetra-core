import { describe, expect, it } from 'vitest';
import {
  InvalidBase32Error,
  decodeBase32,
  encodeBase32,
  isValidBase32,
  normalizeBase32Input,
} from '../../apps/api/src/modules/auth/domain/base32.js';

/**
 * Base32 e o formato que os aplicativos autenticadores exigem para o segredo
 * TOTP. Um erro aqui produz um segredo que nenhum aplicativo consegue ler.
 */
describe('base32 — vetores oficiais da RFC 4648', () => {
  it.each([
    ['', ''],
    ['f', 'MY'],
    ['fo', 'MZXQ'],
    ['foo', 'MZXW6'],
    ['foob', 'MZXW6YQ'],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI'],
  ])('codifica %j sem padding', (entrada, esperado) => {
    expect(encodeBase32(Buffer.from(entrada, 'ascii'))).toBe(esperado);
  });

  it.each([
    ['f', 'MY======'],
    ['fo', 'MZXQ===='],
    ['foo', 'MZXW6==='],
    ['foob', 'MZXW6YQ='],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI======'],
  ])('codifica %j com padding canonico quando solicitado', (entrada, esperado) => {
    expect(encodeBase32(Buffer.from(entrada, 'ascii'), { padding: true })).toBe(esperado);
  });

  it('usa o alfabeto da RFC, sem substituicao', () => {
    const amostra = encodeBase32(Buffer.from(Array.from({ length: 256 }, (_, i) => i)));
    expect(amostra).toMatch(/^[A-Z2-7]+$/);
  });
});

describe('base32 — round-trip', () => {
  it('Buffer vazio', () => {
    expect(decodeBase32(encodeBase32(Buffer.alloc(0)))).toHaveLength(0);
  });

  it('dados simples', () => {
    expect(decodeBase32(encodeBase32(Buffer.from('vetra'))).toString()).toBe('vetra');
  });

  it('bytes arbitrarios, todos os comprimentos de 0 a 64', () => {
    for (let n = 0; n <= 64; n++) {
      const original = Buffer.from(Array.from({ length: n }, (_, i) => (i * 37 + n) % 256));
      expect(decodeBase32(encodeBase32(original)).equals(original)).toBe(true);
      expect(decodeBase32(encodeBase32(original, { padding: true })).equals(original)).toBe(true);
    }
  });

  it('segredo TOTP de 20 bytes', () => {
    const segredo = Buffer.from('12345678901234567890', 'ascii');
    expect(decodeBase32(encodeBase32(segredo)).equals(segredo)).toBe(true);
  });
});

describe('base32 — decodificacao estrita', () => {
  it('aceita entrada com e sem padding', () => {
    expect(decodeBase32('MZXW6YTBOI').toString()).toBe('foobar');
    expect(decodeBase32('MZXW6YTBOI======').toString()).toBe('foobar');
  });

  it('aceita minusculas: base32 e case-insensitive por definicao na RFC', () => {
    expect(decodeBase32('mzxw6ytboi').toString()).toBe('foobar');
  });

  it.each(['MZXW0YTB', 'MZXW1YTB', 'MZXW8YTB', 'MZXW9YTB', 'MZXW+YTB'])(
    'recusa caractere fora do alfabeto: %s',
    (entrada) => {
      expect(() => decodeBase32(entrada)).toThrow(InvalidBase32Error);
    },
  );

  it('recusa padding no meio da entrada', () => {
    expect(isValidBase32('MZ=XW6YTBOI')).toBe(false);
  });

  it('recusa padding em quantidade incorreta', () => {
    expect(isValidBase32('MY=')).toBe(false);
    expect(isValidBase32('MY==')).toBe(false);
  });

  it.each(['M', 'MZX', 'MZXW6Y'])('recusa comprimento impossivel: %s', (entrada) => {
    // Restos validos de um bloco base32 sao 0, 2, 4, 5 e 7. 1, 3 e 6 nao existem.
    expect(isValidBase32(entrada)).toBe(false);
  });

  it('recusa codificacao nao canonica: bits finais nao nulos', () => {
    expect(isValidBase32('MB')).toBe(false);
  });

  it('NAO remove espacos nem hifens em silencio', () => {
    // Transformar entrada invalida em segredo diferente e pior que recusar.
    expect(isValidBase32('MZXW 6YTBOI')).toBe(false);
    expect(isValidBase32('MZXW-6YTBOI')).toBe(false);
  });

  it('a normalizacao para entrada humana e explicita e opcional', () => {
    expect(decodeBase32(normalizeBase32Input('mzxw 6ytb-oi')).toString()).toBe('foobar');
  });
});
