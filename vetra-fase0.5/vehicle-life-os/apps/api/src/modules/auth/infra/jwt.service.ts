import { randomUUID, type KeyObject } from 'node:crypto';
import type { CryptoKey } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { SignJWT, decodeProtectedHeader, importPKCS8, importSPKI, jwtVerify } from 'jose';
import { getEnv } from '../../../config/env.js';
import {
  type JwtKey,
  parseKeySet,
  resolveVerificationKey,
  selectSigningKey,
} from '../domain/jwt-keyset.js';

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
  private readonly keyset = parseKeySet(getEnv().JWT_KEY_SET_JSON);
  private signingKeyCache: { key: JwtKey; parsed: KeyObject | CryptoKey | Uint8Array } | null = null;
  private readonly verificationKeyCache = new Map<string, KeyObject | CryptoKey | Uint8Array>();

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
    const header = decodeProtectedHeader(token);
    if (!header.kid) {
      throw new Error('Token missing kid');
    }
    const matchingKey = resolveVerificationKey(this.keyset, header.kid);
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
  }

  private async resolvePrivateKey(key: JwtKey): Promise<KeyObject | CryptoKey | Uint8Array> {
    if (this.signingKeyCache?.key.kid === key.kid) {
      return this.signingKeyCache.parsed;
    }
    if (!key.private_key_pem) {
      throw new Error(`Chave privada ausente para kid=${key.kid}`);
    }
    const parsed = await importPKCS8(key.private_key_pem, 'EdDSA');
    this.signingKeyCache = { key, parsed };
    return parsed;
  }

  private async resolvePublicKey(key: JwtKey): Promise<KeyObject | CryptoKey | Uint8Array> {
    const cached = this.verificationKeyCache.get(key.kid);
    if (cached) return cached;

    const parsed = await importSPKI(key.public_key_pem, 'EdDSA');
    this.verificationKeyCache.set(key.kid, parsed);
    return parsed;
  }
}
