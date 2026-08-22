import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/**
 * Cifra de envelope para segredos em repouso -- AES-256-GCM, node:crypto.
 *
 * MODULO PURO E AGNOSTICO
 * Ele nao le ambiente, nao conhece MFA, nao conhece user_id e nao conhece
 * nenhuma regra de negocio. Recebe o keyring e a AAD como parametros. A AAD
 * `mfa_totp:{user_id}` e construida pelo servico de MFA no Bloco 5 -- aqui ela
 * e apenas uma string autenticada pelo GCM.
 *
 * Consequencia pratica dessa pureza: um teste consegue montar dois keyrings
 * diferentes no mesmo processo e provar a rotacao de KEK de verdade, sem
 * manipular variavel global.
 *
 * FONTE DA CHAVE
 * Este modulo NAO cria configuracao nova. A APP_KEK ja existe e ja e validada
 * em config/env.ts desde a Fase 0; a ligacao entre ela e o keyring sera feita
 * pelo servico de MFA no Bloco 5, sem inventar variavel de ambiente.
 *
 * O versionamento permite rotacao INCREMENTAL: cada registro guarda a versao
 * com que foi cifrado, e a chave nova passa a valer apenas para registros
 * novos. Nenhuma recriptografia em massa e necessaria.
 */

const ALGORITHM = 'aes-256-gcm';
const NONCE_BYTES = 12; // NIST SP 800-38D
const TAG_BYTES = 16;
const KEY_BYTES = 32;

export interface KekKeyring {
  /** Versao usada quando o chamador nao especifica outra. */
  activeVersion: number;
  keys: ReadonlyMap<number, Buffer>;
}

export interface EncryptedEnvelope {
  /** ciphertext seguido da tag de autenticacao (16 bytes finais). */
  ciphertext: Buffer;
  nonce: Buffer;
  keyVersion: number;
}

export class UnknownKekVersionError extends Error {
  constructor(readonly version: number) {
    super(`versao de KEK ausente do keyring: ${version}`);
    this.name = 'UnknownKekVersionError';
  }
}

export class InvalidEnvelopeInputError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'InvalidEnvelopeInputError';
  }
}

export class DecryptionFailedError extends Error {
  constructor() {
    // Mensagem deliberadamente generica: chave errada, AAD errada, nonce trocado
    // e ciphertext adulterado sao indistinguiveis para quem chama. Distinguir
    // transformaria a funcao em oraculo.
    super('nao foi possivel decifrar');
    this.name = 'DecryptionFailedError';
  }
}

export function buildKeyring(input: {
  activeVersion: number;
  activeKey: Buffer;
  retired?: readonly { version: number; key: Buffer }[];
}): KekKeyring {
  const keys = new Map<number, Buffer>();

  for (const entry of input.retired ?? []) {
    assertKey(entry.key, entry.version);
    keys.set(entry.version, entry.key);
  }

  assertKey(input.activeKey, input.activeVersion);
  keys.set(input.activeVersion, input.activeKey);

  return { activeVersion: input.activeVersion, keys };
}

function assertKey(key: Buffer, version: number): void {
  if (!Number.isInteger(version) || version <= 0) {
    throw new InvalidEnvelopeInputError(`versao de KEK invalida: ${version}`);
  }
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) {
    throw new InvalidEnvelopeInputError(
      `chave da KEK v${version} deve ter exatamente ${KEY_BYTES} bytes`,
    );
  }
}

function resolveKey(keyring: KekKeyring, version: number): Buffer {
  const key = keyring.keys.get(version);
  if (!key) throw new UnknownKekVersionError(version);
  return key;
}

/** AAD e obrigatoria: sem contexto autenticado, o ciphertext e movivel. */
function assertAad(aad: string): Buffer {
  if (typeof aad !== 'string' || aad.length === 0) {
    throw new InvalidEnvelopeInputError('AAD e obrigatoria e nao pode ser vazia');
  }
  return Buffer.from(aad, 'utf8');
}

/**
 * Cifra com a versao indicada, ou com a ativa do keyring.
 *
 * `keyVersion` explicito serve a rotacao: durante a transicao e possivel
 * escolher deliberadamente a versao nova sem depender de qual esta ativa.
 */
export function encrypt(
  keyring: KekKeyring,
  plaintext: Buffer,
  aad: string,
  keyVersion?: number,
): EncryptedEnvelope {
  if (!Buffer.isBuffer(plaintext)) {
    throw new InvalidEnvelopeInputError('plaintext deve ser Buffer');
  }

  const version = keyVersion ?? keyring.activeVersion;
  const key = resolveKey(keyring, version);
  const aadBytes = assertAad(aad);
  const nonce = randomBytes(NONCE_BYTES);

  const cipher = createCipheriv(ALGORITHM, key, nonce);
  cipher.setAAD(aadBytes);

  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return { ciphertext: Buffer.concat([body, tag]), nonce, keyVersion: version };
}

/**
 * Decifra pela versao gravada no registro -- nunca pela ativa.
 *
 * Sem fallback: se a versao nao estiver no keyring, o erro e explicito. Tentar
 * outra chave "para ver se funciona" e exatamente o fallback criptografico
 * silencioso que o contrato proibe.
 */
export function decrypt(
  keyring: KekKeyring,
  ciphertext: Buffer,
  nonce: Buffer,
  aad: string,
  keyVersion: number,
): Buffer {
  const key = resolveKey(keyring, keyVersion);
  const aadBytes = assertAad(aad);

  if (!Buffer.isBuffer(nonce) || nonce.length !== NONCE_BYTES) throw new DecryptionFailedError();
  if (!Buffer.isBuffer(ciphertext) || ciphertext.length < TAG_BYTES) throw new DecryptionFailedError();

  const body = ciphertext.subarray(0, ciphertext.length - TAG_BYTES);
  const tag = ciphertext.subarray(ciphertext.length - TAG_BYTES);

  try {
    const decipher = createDecipheriv(ALGORITHM, key, nonce);
    decipher.setAAD(aadBytes);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    throw new DecryptionFailedError();
  }
}

/** Conveniencia para decifrar direto de um envelope produzido por encrypt(). */
export function decryptEnvelope(
  keyring: KekKeyring,
  envelope: EncryptedEnvelope,
  aad: string,
): Buffer {
  return decrypt(keyring, envelope.ciphertext, envelope.nonce, aad, envelope.keyVersion);
}
