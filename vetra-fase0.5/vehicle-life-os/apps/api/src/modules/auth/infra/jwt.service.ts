import { randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { SignJWT, decodeProtectedHeader, importPKCS8, importSPKI, jwtVerify } from 'jose';
import type { KeyLike } from 'jose';
import { getEnv } from '../../../config/env.js';
import {
  type JwtKey,
  parseKeySet,
  resolveVerificationKey,
  selectSigningKey,
} from '../domain/jwt-keyset.js';

export class InvalidTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidTokenError';
  }
}

export interface AccessTokenClaims {
  sub: string;
  sid: string;
  jti: string;
  amr: string[];
  iss: string;
  aud: string;
}

@Injectable()
export class JwtService {
  private readonly logger = new Logger(JwtService.name);
  private readonly keyset = parseKeySet((getEnv() as unknown as { JWT_KEYS_JSON?: string; JWT_KEY_SET_JSON?: string }).JWT_KEYS_JSON ?? (getEnv() as unknown as { JWT_KEY_SET_JSON?: string }).JWT_KEY_SET_JSON ?? '[]');
  private signingKeyCache: { key: JwtKey; parsed: KeyLike | Uint8Array } | null = null;
  private readonly verificationKeyCache = new Map<string, KeyLike | Uint8Array>();

  async sign(claims: { sub: string; sid: string; amr?: string[] }): Promise<string> {
    return this.signAccessToken(claims);
  }

  async verify(token: string): Promise<AccessTokenClaims> {
    return this.verifyAccessToken(token);
  }

  async signAccessToken(claims: { sub: string; sid: string; amr?: string[] }): Promise<string> {
    const signingKey = selectSigningKey(this.keyset);
    const parsedKey = await this.resolvePrivateKey(signingKey);
    const jti = randomUUID();

    return new SignJWT({
      sid: claims.sid,
      amr: claims.amr ?? ['pwd'],
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: signingKey.kid, typ: 'JWT' })
      .setSubject(claims.sub)
      .setIssuer('urn:vetra:auth')
      .setAudience('urn:vetra:api')
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime('10m')
      .sign(parsedKey);
  }

  async verifyAccessToken(token: string): Promise<AccessTokenClaims> {
    try {
      const header = decodeProtectedHeader(token);
      if (!header.kid) {
        throw new InvalidTokenError('Token missing kid');
      }
      const matchingKey = resolveVerificationKey(this.keyset, header.kid);
      if (!matchingKey) {
        throw new InvalidTokenError(`Unknown kid: ${header.kid}`);
      }
      const parsedKey = await this.resolvePublicKey(matchingKey);

      const { payload } = await jwtVerify(token, parsedKey, {
        issuer: 'urn:vetra:auth',
        audience: 'urn:vetra:api',
        algorithms: ['EdDSA'],
      });

      return {
        sub: payload.sub!,
        sid: payload.sid as string,
        jti: payload.jti!,
        amr: (payload.amr as string[]) ?? ['pwd'],
        iss: payload.iss!,
        aud: typeof payload.aud === 'string' ? payload.aud : payload.aud![0]!,
      };
    } catch (err: unknown) {
      if (err instanceof InvalidTokenError) {
        throw err;
      }
      const message = err instanceof Error ? err.message : 'Invalid token';
      throw new InvalidTokenError(message);
    }
  }

  private async resolvePrivateKey(key: JwtKey): Promise<KeyLike | Uint8Array> {
    if (this.signingKeyCache?.key.kid === key.kid) {
      return this.signingKeyCache.parsed;
    }
    const pem = (key as unknown as { privatePem?: string; private_key_pem?: string }).privatePem ?? (key as unknown as { private_key_pem?: string }).private_key_pem;
    if (!pem) {
      throw new Error(`Chave privada ausente para kid=${key.kid}`);
    }
    const parsed = await importPKCS8(pem, 'EdDSA');
    this.signingKeyCache = { key, parsed };
    return parsed;
  }

  private async resolvePublicKey(key: JwtKey): Promise<KeyLike | Uint8Array> {
    const cached = this.verificationKeyCache.get(key.kid);
    if (cached) return cached;

    const pem = (key as unknown as { publicPem?: string; public_key_pem?: string }).publicPem ?? (key as unknown as { public_key_pem?: string }).public_key_pem;
    if (!pem) {
      throw new Error(`Chave pública ausente para kid=${key.kid}`);
    }
    const parsed = await importSPKI(pem, 'EdDSA');
    this.verificationKeyCache.set(key.kid, parsed);
    return parsed;
  }
}
