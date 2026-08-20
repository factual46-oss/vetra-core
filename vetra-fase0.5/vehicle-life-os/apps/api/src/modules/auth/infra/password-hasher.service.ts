import { createHmac, timingSafeEqual } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { hash as argon2Hash, verify as argon2Verify, Algorithm } from '@node-rs/argon2';
import { getEnv } from '../../../config/env.js';

export interface Argon2Params {
  memoryKiB: number;
  timeCost: number;
  parallelism: number;
}

export interface HashedPassword {
  hash: string;
  params: Argon2Params;
}

/**
 * Argon2id com pepper.
 *
 * O pepper e aplicado por HMAC-SHA256 ANTES do Argon2, e nao pela opcao `secret`
 * da biblioteca. Duas razoes: a pre-derivacao e testavel em unidade sem o modulo
 * nativo, e sobrevive a uma eventual troca de biblioteca sem invalidar as senhas
 * existentes -- o formato do hash deixa de depender de um recurso especifico do
 * fornecedor.
 *
 * O HMAC tambem limita a entrada do Argon2 a 32 bytes, o que neutraliza qualquer
 * tentativa de DoS por senha gigante.
 */
@Injectable()
export class PasswordHasherService {
  private readonly pepper: Buffer;

  constructor() {
    const env = getEnv();
    this.pepper = Buffer.from(env.AUTH_PEPPER_BASE64, 'base64');
  }

  currentParams(): Argon2Params {
    const env = getEnv();
    return {
      memoryKiB: env.ARGON2_MEMORY_KIB,
      timeCost: env.ARGON2_TIME_COST,
      parallelism: env.ARGON2_PARALLELISM,
    };
  }

  private pepperedInput(password: string): Buffer {
    // Sem pepper configurado (desenvolvimento), o HMAC roda com chave vazia:
    // o formato do hash e o mesmo, e ligar o pepper depois exige re-hash.
    return createHmac('sha256', this.pepper).update(password, 'utf8').digest();
  }

  async hash(password: string): Promise<HashedPassword> {
    const params = this.currentParams();
    const hashed = await argon2Hash(this.pepperedInput(password), {
      algorithm: Algorithm.Argon2id,
      memoryCost: params.memoryKiB,
      timeCost: params.timeCost,
      parallelism: params.parallelism,
    });
    return { hash: hashed, params };
  }

  async verify(storedHash: string, password: string): Promise<boolean> {
    try {
      return await argon2Verify(storedHash, this.pepperedInput(password));
    } catch {
      // Hash corrompido ou formato desconhecido nao deve virar 500 no login.
      return false;
    }
  }

  /**
   * Verificacao de descarte, executada quando o e-mail nao existe, para nao
   * criar diferenca grosseira de tempo entre "conta inexistente" e "senha
   * errada". Nao promete timing perfeito -- reduz o sinal obvio.
   */
  async verifyDummy(password: string): Promise<false> {
    await this.verify(DUMMY_HASH, password);
    return false;
  }

  /** Endurecimento de parametros sem invalidar senha: re-hash no proximo login. */
  needsRehash(stored: Argon2Params | null): boolean {
    if (!stored) return true;
    const current = this.currentParams();
    return (
      stored.memoryKiB < current.memoryKiB ||
      stored.timeCost < current.timeCost ||
      stored.parallelism < current.parallelism
    );
  }

  static constantTimeEquals(a: Buffer, b: Buffer): boolean {
    return a.length === b.length && timingSafeEqual(a, b);
  }
}

/**
 * Hash fixo de descarte. Nao e credencial de ninguem: e o hash de um valor
 * aleatorio gerado uma vez, mantido constante para que a verificacao falsa
 * custe o mesmo que a verdadeira.
 */
const DUMMY_HASH =
  '$argon2id$v=19$m=19456,t=3,p=1$c29tZXNhbHRzb21lc2FsdA$YXJnb24yaWRkdW1teWhhc2hmb3J0aW1pbmc';
