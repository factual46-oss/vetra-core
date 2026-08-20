import { describe, expect, it } from 'vitest';
import { InvalidEmailError, isValidEmail, normalizeEmail } from '../../apps/api/src/modules/auth/domain/email.js';
import { checkPassword } from '../../apps/api/src/modules/auth/domain/password-policy.js';
import {
  generateOpaqueToken,
  hashOpaqueToken,
  looksLikeOpaqueToken,
  opaqueTokenMatches,
} from '../../apps/api/src/modules/auth/domain/opaque-token.js';
import {
  KeySetError,
  parseKeySet,
  resolveVerificationKey,
  selectSigningKey,
} from '../../apps/api/src/modules/auth/domain/jwt-keyset.js';

describe('normalizacao de e-mail', () => {
  it('aplica minusculas e remove espacos nas bordas', () => {
    expect(normalizeEmail('  User@Example.COM  ')).toBe('user@example.com');
  });

  it('aplica NFKC: caracteres de largura total viram ASCII', () => {
    expect(normalizeEmail('ｕｓｅｒ@example.com')).toBe('user@example.com');
  });

  it('NAO remove sufixo +tag -- politica documentada', () => {
    expect(normalizeEmail('alguem+vetra@example.com')).toBe('alguem+vetra@example.com');
  });

  it('NAO remove pontos: fundir identidades seria irreversivel', () => {
    expect(normalizeEmail('a.b@example.com')).toBe('a.b@example.com');
  });

  it('USER@X.COM e user@x.com sao a mesma identidade', () => {
    expect(normalizeEmail('USER@X.COM')).toBe(normalizeEmail('user@x.com'));
  });

  it.each(['sem-arroba', 'user@localhost', 'us er@x.com', '   ', 'a@b', '@x.com', 'a@.com'])(
    'rejeita %j',
    (value) => {
      expect(isValidEmail(value)).toBe(false);
    },
  );

  it('rejeita e-mail acima de 254 caracteres', () => {
    expect(() => normalizeEmail(`${'a'.repeat(250)}@x.com`)).toThrow(InvalidEmailError);
  });

  it('rejeita caractere de controle', () => {
    expect(isValidEmail('user\u0000@x.com')).toBe(false);
  });
});

describe('politica de senha', () => {
  it('aceita frase longa sem regra de composicao', () => {
    expect(checkPassword('cavalo bateria grampo').ok).toBe(true);
  });

  it('rejeita senha curta', () => {
    expect(checkPassword('curta123').rejection).toBe('TOO_SHORT');
  });

  it('rejeita apenas espacos', () => {
    expect(checkPassword('              ').rejection).toBe('ONLY_WHITESPACE');
  });

  it('rejeita caractere repetido', () => {
    expect(checkPassword('aaaaaaaaaaaaaa').rejection).toBe('REPEATED_CHARACTER');
  });

  it('rejeita senha absurdamente longa', () => {
    expect(checkPassword('a1'.repeat(600)).rejection).toBe('TOO_LONG');
  });
});

describe('tokens opacos', () => {
  it('gera 256 bits em base64url', () => {
    expect(looksLikeOpaqueToken(generateOpaqueToken().raw)).toBe(true);
  });

  it('hash tem 32 bytes e e deterministico', () => {
    const token = generateOpaqueToken();
    expect(token.hash).toHaveLength(32);
    expect(hashOpaqueToken(token.raw).equals(token.hash)).toBe(true);
  });

  it('confere o proprio token', () => {
    const token = generateOpaqueToken();
    expect(opaqueTokenMatches(token.raw, token.hash)).toBe(true);
  });

  it('nao confere token alheio', () => {
    const token = generateOpaqueToken();
    expect(opaqueTokenMatches(generateOpaqueToken().raw, token.hash)).toBe(false);
  });

  it('nao repete valores', () => {
    const values = new Set(Array.from({ length: 200 }, () => generateOpaqueToken().raw));
    expect(values.size).toBe(200);
  });

  it('recusa formato invalido', () => {
    expect(looksLikeOpaqueToken('curto')).toBe(false);
    expect(looksLikeOpaqueToken(null)).toBe(false);
  });
});

describe('conjunto de chaves de assinatura', () => {
  const pem = (kind: string) => `-----BEGIN ${kind} KEY-----\n${'A'.repeat(120)}\n-----END ${kind} KEY-----`;
  const key = (kid: string, status: 'active' | 'next' | 'retiring') => ({
    kid,
    status,
    privatePem: pem('PRIVATE'),
    publicPem: pem('PUBLIC'),
  });

  it('assina sempre com a chave active', () => {
    expect(selectSigningKey([key('k1', 'active'), key('k2', 'retiring')]).kid).toBe('k1');
  });

  it('verifica com a chave retiring: e o periodo de graca', () => {
    const keys = [key('k1', 'active'), key('k2', 'retiring')];
    expect(resolveVerificationKey(keys, 'k2')?.kid).toBe('k2');
  });

  it('verifica com a chave next, que ainda nao assina', () => {
    const keys = [key('k1', 'active'), key('k3', 'next')];
    expect(resolveVerificationKey(keys, 'k3')?.kid).toBe('k3');
  });

  it('kid desconhecido nao resolve', () => {
    expect(resolveVerificationKey([key('k1', 'active')], 'invasor')).toBeUndefined();
  });

  it('rejeita kid duplicado', () => {
    expect(() => parseKeySet([key('k1', 'active'), key('k1', 'next')], true)).toThrow(KeySetError);
  });

  it('rejeita conjunto sem chave active em producao', () => {
    expect(() => parseKeySet([key('k1', 'next')], true)).toThrow(KeySetError);
  });

  it('rejeita duas chaves active', () => {
    expect(() => parseKeySet([key('k1', 'active'), key('k2', 'active')], true)).toThrow(KeySetError);
  });

  it('rejeita PEM invalido', () => {
    expect(() => parseKeySet([{ ...key('k1', 'active'), privatePem: 'xx' }], true)).toThrow(KeySetError);
  });

  it('permite conjunto sem active fora de producao', () => {
    expect(parseKeySet([key('k1', 'next')], false)).toHaveLength(1);
  });
});
