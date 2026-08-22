import { describe, expect, it } from 'vitest';
import {
  InvalidTotpInputError,
  TOTP_PERIOD_SECONDS,
  counterForTimestamp,
  findMatchingStep,
  generateTotp,
  generateTotpSecret,
  hotp,
  verifyTotp,
} from '../../apps/api/src/modules/auth/domain/totp.js';

/**
 * O algoritmo se prova contra um PADRAO PUBLICADO, nao contra si mesmo.
 *
 * Os vetores do Apendice B da RFC 6238 usam a seed ASCII "12345678901234567890"
 * e codigos de OITO digitos. Sao usados aqui exatamente como publicados.
 *
 * Nenhum teste usa sleep() nem o relogio real: todo timestamp e explicito.
 */
const SEED = Buffer.from('12345678901234567890', 'ascii');
const ms = (segundos: number) => segundos * 1000;

describe('TOTP — vetores oficiais da RFC 6238 (HMAC-SHA1)', () => {
  it.each([
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ])('T = %i s produz %s', (segundos, esperado) => {
    expect(generateTotp(SEED, ms(segundos), { digits: 8 })).toBe(esperado);
  });

  it('preserva o ZERO A ESQUERDA — o defeito classico de implementacao', () => {
    // Converter o resultado para numero produziria 7081804, que nunca confere.
    const codigo = generateTotp(SEED, ms(1111111109), { digits: 8 });
    expect(codigo).toBe('07081804');
    expect(codigo).toHaveLength(8);
  });

  it('gera exatamente 6 digitos por padrao, sempre com padding', () => {
    for (let t = 0; t < 4000; t += 41) {
      expect(generateTotp(SEED, ms(t))).toMatch(/^\d{6}$/);
    }
  });

  it('o contador avanca a cada 30 segundos, e nao antes', () => {
    expect(counterForTimestamp(ms(0))).toBe(0);
    expect(counterForTimestamp(ms(29))).toBe(0);
    expect(counterForTimestamp(ms(30))).toBe(1);
    expect(counterForTimestamp(ms(59))).toBe(1);
    expect(TOTP_PERIOD_SECONDS).toBe(30);
  });

  it('hotp e deterministico e muda com o contador', () => {
    expect(hotp(SEED, 1)).toBe(hotp(SEED, 1));
    expect(hotp(SEED, 1)).not.toBe(hotp(SEED, 2));
  });
});

describe('TOTP — janela de aceitacao', () => {
  const agora = ms(1111111111);

  it('aceita o passo atual', () => {
    expect(verifyTotp(SEED, generateTotp(SEED, agora), agora)).toBe(true);
  });

  it('aceita T-1 e T+1: ~90 s de tolerancia para relogio dessincronizado', () => {
    expect(verifyTotp(SEED, generateTotp(SEED, agora - ms(30)), agora)).toBe(true);
    expect(verifyTotp(SEED, generateTotp(SEED, agora + ms(30)), agora)).toBe(true);
  });

  it('RECUSA T-2 e T+2: a janela e explicitamente +-1', () => {
    expect(verifyTotp(SEED, generateTotp(SEED, agora - ms(60)), agora)).toBe(false);
    expect(verifyTotp(SEED, generateTotp(SEED, agora + ms(60)), agora)).toBe(false);
  });

  it('findMatchingStep devolve QUAL passo casou', () => {
    // O anti-replay do Bloco 5 depende deste valor para o UPDATE condicional em
    // last_used_step. Sem ele, o servico cairia no padrao SELECT-verifica-UPDATE.
    expect(findMatchingStep(SEED, generateTotp(SEED, agora), agora)).toBe(counterForTimestamp(agora));
    expect(findMatchingStep(SEED, generateTotp(SEED, agora - ms(30)), agora)).toBe(
      counterForTimestamp(agora) - 1,
    );
  });

  it('findMatchingStep devolve null quando nao ha correspondencia', () => {
    expect(findMatchingStep(SEED, '000000', agora)).toBeNull();
  });

  it('recusa codigo de outro segredo', () => {
    expect(verifyTotp(SEED, generateTotp(generateTotpSecret(), agora), agora)).toBe(false);
  });
});

describe('TOTP — entradas invalidas', () => {
  const agora = ms(1111111111);

  it.each([
    ['5 digitos', '12345'],
    ['7 digitos', '1234567'],
    ['vazio', ''],
    ['nao numerico', 'abcdef'],
    ['numerico com letra', '12345a'],
    ['com espaco', '12 345'],
  ])('recusa codigo %s', (_descricao, codigo) => {
    expect(verifyTotp(SEED, codigo, agora)).toBe(false);
  });

  it('rejeita segredo vazio', () => {
    expect(() => generateTotp(Buffer.alloc(0), agora)).toThrow(InvalidTotpInputError);
  });

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    'rejeita timestamp invalido: %s',
    (timestamp) => {
      expect(() => generateTotp(SEED, timestamp)).toThrow(InvalidTotpInputError);
    },
  );

  it.each([
    ['digits abaixo do minimo', { digits: 4 }],
    ['digits acima do maximo', { digits: 11 }],
    ['periodo zero', { periodSeconds: 0 }],
    ['periodo negativo', { periodSeconds: -30 }],
    ['janela negativa', { window: -1 }],
    ['t0 negativo', { t0Seconds: -1 }],
  ])('rejeita opcao invalida: %s', (_descricao, options) => {
    expect(() => generateTotp(SEED, agora, options)).toThrow(InvalidTotpInputError);
  });

  it('rejeita tamanho de segredo abaixo do minimo', () => {
    expect(() => generateTotpSecret(8)).toThrow(InvalidTotpInputError);
  });

  it('gera segredo de 160 bits a partir de CSPRNG', () => {
    const a = generateTotpSecret();
    expect(a).toHaveLength(20);
    expect(a.equals(generateTotpSecret())).toBe(false);
  });
});
