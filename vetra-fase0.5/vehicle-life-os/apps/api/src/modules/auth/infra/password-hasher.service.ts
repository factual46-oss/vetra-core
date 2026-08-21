import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
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
 * existentes. O HMAC tambem limita a entrada do Argon2 a 32 bytes, o que
 * neutraliza DoS por senha gigante.
 */
@Injectable()
export class PasswordHasherService {
  private readonly logger = new Logger(PasswordHasherService.name);
  private readonly pepper: Buffer;

  /**
   * FIX-1A-01: o hash de descarte precisa ser um Argon2 DE VERDADE.
   *
   * A versao anterior tinha uma string escrita a mao que apenas PARECIA um hash
   * Argon2. Consequencia: argon2Verify lancava erro de formato, o catch engolia,
   * e verifyDummy retornava em ~0ms -- destruindo a equalizacao de tempo que
   * ela existe para garantir. Agora e gerado uma vez, sob demanda, a partir de
   * bytes aleatorios: nao e credencial de ninguem e custa exatamente o mesmo que
   * uma verificacao real.
   */
  private dummyHash: string | null = null;

  constructor() {
    this.pepper = Buffer.from(getEnv().AUTH_PEPPER_BASE64, 'base64');
  }

  currentParams(): Argon2Params {
    const env = getEnv();
    return {
      memoryKiB: env.ARGON2_MEMORY_KIB,
      timeCost: env.ARGON2_TIME_COST,
      parallelism: env.ARGON2_PARALLELISM,
    };
  }

  private argon2Options(params: Argon2Params) {
    return {
      algorithm: Algorithm.Argon2id,
      memoryCost: params.memoryKiB,
      timeCost: params.timeCost,
      parallelism: params.parallelism,
    };
  }

  private pepperedInput(password: string): Buffer {
    return createHmac('sha256', this.pepper).update(password, 'utf8').digest();
  }

  async hash(password: string): Promise<HashedPassword> {
    const params = this.currentParams();
    const hashed = await argon2Hash(this.pepperedInput(password), this.argon2Options(params));
    return { hash: hashed, params };
  }

  async verify(storedHash: string, password: string): Promise<boolean> {
    try {
      return await argon2Verify(storedHash, this.pepperedInput(password));
    } catch (err) {
      /**
       * FIX-1A-02: senha errada NAO lanca excecao -- argon2Verify devolve false.
       * Cair aqui significa que algo esta quebrado: hash corrompido, formato
       * desconhecido, biblioteca incompativel. Continuamos devolvendo false para
       * nao virar 500 no login, mas agora isso DEIXA RASTRO.
       *
       * A versao anterior engolia em silencio, e um erro de biblioteca virava
       * "senha incorreta" para todos os usuarios -- exatamente a falha que
       * derrubou 10 testes sem apontar a causa.
       */
      this.logger.error(
        { err, hashPrefix: storedHash.slice(0, 24), hashLength: storedHash.length },
        'falha ao verificar senha: o hash armazenado nao pode ser processado',
      );
      return false;
    }
  }

  /**
   * Verificacao de descarte, executada quando o e-mail nao existe, para nao
   * criar diferenca grosseira de tempo entre "conta inexistente" e "senha
   * errada". Nao promete timing perfeito -- remove o sinal obvio.
   */
  async verifyDummy(password: string): Promise<false> {
    this.dummyHash ??= await argon2Hash(randomBytes(32), this.argon2Options(this.currentParams()));
    await this.verify(this.dummyHash, password);
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
