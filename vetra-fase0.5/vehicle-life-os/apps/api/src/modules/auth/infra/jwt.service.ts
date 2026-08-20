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
  readonly kind: 'BAD_ALGORITHM' | 'UNKNOWN_KID' | 'MISSING_KID' | 'EXPIRED' | 'INVALID_SIGNATURE' | 'MALFORMED';
  readonly kid?: string;

  constructor(
    kind: 'BAD_ALGORITHM' | 'UNKNOWN_KID' | 'MISSING_KID' | 'EXPIRED' | 'INVALID_SIGNATURE' | 'MALFORMED',
    message: string,
    kid?: string,
  ) {
    super(message);
    this.name = 'InvalidTokenError';
    this.kind = kind;
    this.kid = kid;
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

export interface SignTokenResult {
  token: string;
  expiresInSeconds: number;
}

export interface SignTokenParams {
  userId?: string;
  sessionId?: string;
  sub?: string;
  sid?: string;
  amr?: string[];
}

@Injectable()
export class JwtService {
  private readonly logger = new Logger(JwtService.name);
  private keyset: JwtKey[] | null = null;
  private signingKeyCache: { key: JwtKey; parsed: KeyLike | Uint8Array } | null = null;
  private readonly verificationKeyCache = new Map<string, KeyLike | Uint8Array>();

  constructor() {
    this.loadKeyset();
  }

  private loadKeyset(): JwtKey[] | null {
    if (this.keyset && this.keyset.length > 0) return this.keyset;
    try {
      const env = getEnv() as unknown as { JWT_KEYS_JSON?: string; JWT_KEY_SET_JSON?: string };
      const rawJson = env.JWT_KEYS_JSON ?? env.JWT_KEY_SET_JSON ?? process.env.JWT_KEYS_JSON ?? process.env.JWT_KEY_SET_JSON;
      if (rawJson) {
        this.keyset = parseKeySet(rawJson);
        return this.keyset;
      }
    } catch {
      // Ignora durante instanciação se o ambiente ainda não foi injetado
    }
    return null;
  }

  private ensureKeyset(): JwtKey[] {
    const keyset = this.loadKeyset();
    if (!keyset || keyset.length === 0) {
      throw new Error('JWT Keyset não configurado');
    }
    return keyset;
  }

  async sign(params: SignTokenParams): Promise<SignTokenResult> {
    const sub = params.userId ?? params.sub;
    const sid = params.sessionId ?? params.sid;

    if (!sub || !sid) {
      throw new Error('sub and sid are required to sign an access token');
    }

    const keyset = this.ensureKeyset();
    const signingKey = selectSigningKey(keyset, new Date());
    const parsedKey = await this.resolvePrivateKey(signingKey);
    const jti = randomUUID();
    const expiresInSeconds = 600;

    const token = await new SignJWT({
      sid,
      amr: params.amr ?? ['pwd'],
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: signingKey.kid, typ: 'JWT' })
      .setSubject(sub)
      .setIssuer('urn:vetra:auth')
      .setAudience('urn:vetra:api')
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime('10m')
      .sign(parsedKey);

    return {
      token,
      expiresInSeconds,
    };
  }

  async verify(token: string): Promise<AccessTokenClaims> {
    let header: { alg?: string; kid?: string };
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new InvalidTokenError('MALFORMED', 'Token cannot be decoded');
    }

    if (!header.kid) {
      throw new InvalidTokenError('MISSING_KID', 'Token missing kid header');
    }

    if (header.alg !== 'EdDSA') {
      throw new InvalidTokenError('BAD_ALGORITHM', `Unsupported algorithm: ${header.alg}`);
    }

    const keyset = this.ensureKeyset();
    const matchingKey = resolveVerificationKey(keyset, header.kid, new Date());
    if (!matchingKey) {
      throw new InvalidTokenError('UNKNOWN_KID', `Unknown or expired key id: ${header.kid}`, header.kid);
    }

    const parsedKey = await this.resolvePublicKey(matchingKey);

    try {
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
      const code = (err as { code?: string }).code;
      if (code === 'ERR_JWT_EXPIRED') {
        throw new InvalidTokenError('EXPIRED', 'Token has expired');
      }
      throw new InvalidTokenError('INVALID_SIGNATURE', err instanceof Error ? err.message : 'Invalid signature');
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
