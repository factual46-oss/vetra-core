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

@Injectable()
export class PasswordHasherService {
  private readonly logger = new Logger(PasswordHasherService.name);
  private readonly pepper: Buffer;
  private dummyHash: string | null = null;

  constructor() {
    const env = getEnv() as unknown as { AUTH_PEPPER_BASE64?: string; AUTH_PEPPER?: string };
    const raw = env.AUTH_PEPPER_BASE64 ?? process.env['AUTH_PEPPER_BASE64'];
    if (raw) {
      this.pepper = Buffer.from(raw, 'base64');
    } else {
      this.pepper = Buffer.alloc(32, 7);
    }
  }

  currentParams(): Argon2Params {
    const env = getEnv() as unknown as {
      ARGON2_MEMORY_KIB?: number;
      ARGON2_TIME_COST?: number;
      ARGON2_PARALLELISM?: number;
    };
    return {
      memoryKiB: Number(env.ARGON2_MEMORY_KIB ?? 19456),
      timeCost: Number(env.ARGON2_TIME_COST ?? 2),
      parallelism: Number(env.ARGON2_PARALLELISM ?? 1),
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

  private pepperedInput(password: string): string {
    return createHmac('sha256', this.pepper).update(password, 'utf8').digest('hex');
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
      this.logger.error(
        { err, hashPrefix: storedHash.slice(0, 24), hashLength: storedHash.length },
        'falha ao verificar senha: o hash armazenado nao pode ser processado',
      );
      return false;
    }
  }

  async verifyDummy(password: string): Promise<false> {
    this.dummyHash ??= await argon2Hash(randomBytes(32).toString('hex'), this.argon2Options(this.currentParams()));
    await this.verify(this.dummyHash, password);
    return false;
  }

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
