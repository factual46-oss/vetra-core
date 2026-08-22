import { describe, expect, it } from 'vitest';
import {
  DecryptionFailedError,
  InvalidEnvelopeInputError,
  UnknownKekVersionError,
  buildKeyring,
  decrypt,
  decryptEnvelope,
  encrypt,
} from '../../apps/api/src/modules/auth/infra/envelope-crypto.js';

/**
 * A APP_KEK existe e e validada desde a Fase 0, mas nunca cifrou nada. O TOTP
 * sera o primeiro uso real -- o que significa que a ROTACAO nunca foi
 * exercitada. Se o segredo do segundo fator for cifrado sem prever isso,
 * rotacionar a chave depois invalida o MFA de todo mundo de uma vez.
 *
 * Por isso os testes de versionamento nao sao acessorios: sao o motivo de o
 * modulo receber um keyring em vez de uma chave.
 *
 * A AAD aqui e apenas uma string. O modulo nao conhece MFA nem user_id --
 * a regra `mfa_totp:{user_id}` pertence ao servico de MFA do Bloco 5.
 */
const K1 = Buffer.alloc(32, 1);
const K2 = Buffer.alloc(32, 2);
const K_ERRADA = Buffer.alloc(32, 9);

const AAD_A = 'contexto:A';
const AAD_B = 'contexto:B';

const ringV1 = buildKeyring({ activeVersion: 1, activeKey: K1 });
const ringV2ComV1 = buildKeyring({ activeVersion: 2, activeKey: K2, retired: [{ version: 1, key: K1 }] });
const ringApenasV2 = buildKeyring({ activeVersion: 2, activeKey: K2 });

const SEGREDO = Buffer.from('segredo-de-vinte-byte', 'utf8');

describe('envelope AES-256-GCM — caminho normal', () => {
  it('1. round-trip devolve exatamente o texto original', () => {
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    expect(decryptEnvelope(ringV1, envelope, AAD_A).equals(SEGREDO)).toBe(true);
  });

  it('2. aceita plaintext vazio', () => {
    const envelope = encrypt(ringV1, Buffer.alloc(0), AAD_A);
    expect(decryptEnvelope(ringV1, envelope, AAD_A)).toHaveLength(0);
  });

  it('3. aceita plaintext binario arbitrario', () => {
    const binario = Buffer.from([0x00, 0xff, 0x80, 0x00, 0x07, 0x0a]);
    expect(decryptEnvelope(ringV1, encrypt(ringV1, binario, AAD_A), AAD_A).equals(binario)).toBe(true);
  });

  it('o ciphertext nao contem o texto em claro', () => {
    expect(encrypt(ringV1, SEGREDO, AAD_A).ciphertext.includes(SEGREDO)).toBe(false);
  });

  it('10. duas cifragens do mesmo plaintext usam nonces diferentes', () => {
    const nonces = new Set(
      Array.from({ length: 200 }, () => encrypt(ringV1, SEGREDO, AAD_A).nonce.toString('hex')),
    );
    expect(nonces.size).toBe(200);
  });

  it('duas cifragens do mesmo plaintext produzem ciphertexts diferentes', () => {
    const a = encrypt(ringV1, SEGREDO, AAD_A);
    const b = encrypt(ringV1, SEGREDO, AAD_A);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
  });
});

describe('envelope AES-256-GCM — integridade e autenticacao', () => {
  it('4. ciphertext adulterado e recusado', () => {
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    const adulterado = { ...envelope, ciphertext: Buffer.from(envelope.ciphertext) };
    adulterado.ciphertext[0] = adulterado.ciphertext[0]! ^ 0xff;
    expect(() => decryptEnvelope(ringV1, adulterado, AAD_A)).toThrow(DecryptionFailedError);
  });

  it('5. tag de autenticacao adulterada e recusada', () => {
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    const adulterado = { ...envelope, ciphertext: Buffer.from(envelope.ciphertext) };
    const ultimo = adulterado.ciphertext.length - 1;
    adulterado.ciphertext[ultimo] = adulterado.ciphertext[ultimo]! ^ 0xff;
    expect(() => decryptEnvelope(ringV1, adulterado, AAD_A)).toThrow(DecryptionFailedError);
  });

  it('6. nonce adulterado e recusado', () => {
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    const adulterado = { ...envelope, nonce: Buffer.from(envelope.nonce) };
    adulterado.nonce[0] = adulterado.nonce[0]! ^ 0xff;
    expect(() => decryptEnvelope(ringV1, adulterado, AAD_A)).toThrow(DecryptionFailedError);
  });

  it('nonce de tamanho invalido e recusado', () => {
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    expect(() => decrypt(ringV1, envelope.ciphertext, Buffer.alloc(8), AAD_A, 1)).toThrow(
      DecryptionFailedError,
    );
  });

  it('ciphertext truncado e recusado', () => {
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    expect(() => decrypt(ringV1, envelope.ciphertext.subarray(0, 8), envelope.nonce, AAD_A, 1)).toThrow(
      DecryptionFailedError,
    );
  });

  it('7. AAD adulterada e recusada', () => {
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    expect(() => decryptEnvelope(ringV1, envelope, `${AAD_A}x`)).toThrow(DecryptionFailedError);
  });

  it('8 e 15. ciphertext nao se move entre AADs', () => {
    // E o que impede mover a linha de um usuario para outro no banco.
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    expect(() => decryptEnvelope(ringV1, envelope, AAD_B)).toThrow(DecryptionFailedError);
  });

  it('chave incorreta na mesma versao e recusada', () => {
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    const ringErrado = buildKeyring({ activeVersion: 1, activeKey: K_ERRADA });
    expect(() => decryptEnvelope(ringErrado, envelope, AAD_A)).toThrow(DecryptionFailedError);
  });

  it('a mensagem de erro nao distingue chave errada de AAD errada', () => {
    // Distinguir transformaria a funcao em oraculo.
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    const capturar = (fn: () => unknown): string => {
      try {
        fn();
        return 'sem erro';
      } catch (err) {
        return (err as Error).message;
      }
    };
    const porAad = capturar(() => decryptEnvelope(ringV1, envelope, AAD_B));
    const porChave = capturar(() =>
      decryptEnvelope(buildKeyring({ activeVersion: 1, activeKey: K_ERRADA }), envelope, AAD_A),
    );
    expect(porAad).toBe(porChave);
  });
});

describe('envelope AES-256-GCM — versionamento e rotacao da KEK', () => {
  it('11. o envelope registra a versao usada', () => {
    expect(encrypt(ringV1, SEGREDO, AAD_A).keyVersion).toBe(1);
  });

  it('12. decifra com a versao correta', () => {
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    expect(decrypt(ringV1, envelope.ciphertext, envelope.nonce, AAD_A, 1).equals(SEGREDO)).toBe(true);
  });

  it('13. versao inexistente falha explicitamente, sem tentar outra chave', () => {
    // Tentar outra chave "para ver se funciona" seria fallback criptografico
    // silencioso -- exatamente o que o contrato proibe.
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    expect(() => decrypt(ringV1, envelope.ciphertext, envelope.nonce, AAD_A, 99)).toThrow(
      UnknownKekVersionError,
    );
  });

  it('14a. ROTACAO: registro cifrado em v1 continua decifravel apos a chave v2 entrar', () => {
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    expect(decryptEnvelope(ringV2ComV1, envelope, AAD_A).equals(SEGREDO)).toBe(true);
  });

  it('14b. apos a rotacao, novos registros nascem na versao ativa', () => {
    expect(encrypt(ringV2ComV1, SEGREDO, AAD_A).keyVersion).toBe(2);
  });

  it('14c. a versao pode ser escolhida explicitamente durante a transicao', () => {
    const envelope = encrypt(ringV2ComV1, SEGREDO, AAD_A, 1);
    expect(envelope.keyVersion).toBe(1);
    expect(decryptEnvelope(ringV1, envelope, AAD_A).equals(SEGREDO)).toBe(true);
  });

  it('registro v1 deixa de abrir se a chave v1 sair do keyring', () => {
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    expect(() => decryptEnvelope(ringApenasV2, envelope, AAD_A)).toThrow(UnknownKekVersionError);
  });

  it('rotacao e incremental: nao exige recifrar tudo de uma vez', () => {
    const antigo = encrypt(ringV1, SEGREDO, AAD_A);
    const novo = encrypt(ringV2ComV1, SEGREDO, AAD_A);
    expect(antigo.keyVersion).toBe(1);
    expect(novo.keyVersion).toBe(2);
    expect(decryptEnvelope(ringV2ComV1, antigo, AAD_A).equals(SEGREDO)).toBe(true);
    expect(decryptEnvelope(ringV2ComV1, novo, AAD_A).equals(SEGREDO)).toBe(true);
  });
});

describe('envelope AES-256-GCM — validacao de entrada', () => {
  it.each([8, 16, 24, 31, 33, 64])('9. rejeita chave de %i bytes', (tamanho) => {
    expect(() => buildKeyring({ activeVersion: 1, activeKey: Buffer.alloc(tamanho) })).toThrow(
      InvalidEnvelopeInputError,
    );
  });

  it('rejeita versao de KEK invalida', () => {
    expect(() => buildKeyring({ activeVersion: 0, activeKey: K1 })).toThrow(InvalidEnvelopeInputError);
    expect(() => buildKeyring({ activeVersion: -1, activeKey: K1 })).toThrow(InvalidEnvelopeInputError);
  });

  it('rejeita AAD vazia: sem contexto autenticado, o ciphertext e movivel', () => {
    expect(() => encrypt(ringV1, SEGREDO, '')).toThrow(InvalidEnvelopeInputError);
  });

  it('rejeita AAD vazia tambem na decifra', () => {
    const envelope = encrypt(ringV1, SEGREDO, AAD_A);
    expect(() => decryptEnvelope(ringV1, envelope, '')).toThrow(InvalidEnvelopeInputError);
  });

  it('a chave ativa prevalece sobre uma retirada de mesma versao', () => {
    const ring = buildKeyring({ activeVersion: 1, activeKey: K1, retired: [{ version: 1, key: K_ERRADA }] });
    expect(decryptEnvelope(ringV1, encrypt(ring, SEGREDO, AAD_A), AAD_A).equals(SEGREDO)).toBe(true);
  });
});
