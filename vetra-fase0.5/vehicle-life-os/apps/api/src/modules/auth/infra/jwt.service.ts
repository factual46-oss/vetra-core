import { randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { SignJWT, decodeJwt, decodeProtectedHeader, errors, importPKCS8, importSPKI, jwtVerify } from 'jose';
import type { KeyLike } from 'jose';
import { getEnv } from '../../../config/env.js';
import {
  type JwtKey,
  parseKeySet,
  resolveVerificationKey,
  selectSigningKey,
} from '../domain/jwt-keyset.js';

export interface AccessTokenClaims {
  sub: string;
  userId: string;
  sid: string;
  sessionId: string;
  jti: string;
  amr: string[];
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  [key: string]: unknown;
}

export class InvalidTokenError extends Error {
  constructor(
    readonly kind:
      | 'MALFORMED'
      | 'UNKNOWN_KID'
      | 'BAD_SIGNATURE'
      | 'EXPIRED'
      | 'BAD_CLAIMS'
      | 'BAD_ALGORITHM',
    readonly kid?: string,
  ) {
    super(kind);
    this.name = 'InvalidTokenError';
  }
}

const ALG = 'EdDSA';

@Injectable()
export class JwtService {
  private readonly logger = new Logger(JwtService.name);
  private readonly keys: JwtKey[];
  private readonly privateKeys = new Map<string, KeyLike | Uint8Array>();
  private readonly publicKeys = new Map<string, KeyLike | Uint8Array>();

  constructor() {
    const env = getEnv();
    let raw: JwtKey[];
    try {
      raw = JSON.parse(env.JWT_KEYS_JSON) as JwtKey[];
    } catch {
      throw new Error('JWT_KEYS_JSON nao e JSON valido');
    }
    this.keys = parseKeySet(raw, env.NODE_ENV === 'production');
  }

  private async privateKeyFor(key: JwtKey): Promise<KeyLike | Uint8Array> {
    const cached = this.privateKeys.get(key.kid);
    if (cached) return cached;
    const imported = await importPKCS8(key.privatePem, ALG);
    this.privateKeys.set(key.kid, imported);
    return imported;
  }

  private async publicKeyFor(key: JwtKey): Promise<KeyLike | Uint8Array> {
    const cached = this.publicKeys.get(key.kid);
    if (cached) return cached;
    const imported = await importSPKI(key.publicPem, ALG);
    this.publicKeys.set(key.kid, imported);
    return imported;
  }

  async sign(input: { userId: string; sessionId: string; amr?: string[] }): Promise<{
    token: string;
    jti: string;
    expiresInSeconds: number;
  }> {
    const env = getEnv();
    const key = selectSigningKey(this.keys);
    const jti = randomUUID();
    const amr = input.amr ?? ['pwd'];

    const token = await new SignJWT({ sid: input.sessionId, amr, jti })
      .setProtectedHeader({ alg: ALG, kid: key.kid, typ: 'JWT' })
      .setSubject(input.userId)
      .setIssuer(env.JWT_ISSUER)
      .setAudience(env.JWT_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(`${env.ACCESS_TOKEN_TTL_SECONDS}s`)
      .sign(await this.privateKeyFor(key));

    return { token, jti, expiresInSeconds: env.ACCESS_TOKEN_TTL_SECONDS };
  }

  async verify(token: string): Promise<AccessTokenClaims> {
    const env = getEnv();

    let header: { alg?: string; kid?: string };
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new InvalidTokenError('MALFORMED');
    }

    if (header.alg !== ALG) throw new InvalidTokenError('BAD_ALGORITHM');

    const key = resolveVerificationKey(this.keys, header.kid);
    if (!key) {
      this.logger.warn({ kid: header.kid }, 'token com kid desconhecido');
      throw new InvalidTokenError('UNKNOWN_KID', typeof header.kid === 'string' ? header.kid : undefined);
    }

    // Pré-validação de expiração estrita
    try {
      const unverified = decodeJwt(token);
      if (unverified.exp && unverified.exp * 1000 < Date.now()) {
        throw new InvalidTokenError('EXPIRED');
      }
    } catch (e) {
      if (e instanceof InvalidTokenError) throw e;
    }

    try {
      const { payload } = await jwtVerify(token, await this.publicKeyFor(key), {
        algorithms: [ALG],
        issuer: env.JWT_ISSUER,
        audience: env.JWT_AUDIENCE,
      });

      const sid = (payload['sid'] ?? payload['sessionId']) as string | undefined;
      const sub = payload.sub;

      if (typeof sub !== 'string' || typeof sid !== 'string') {
        throw new InvalidTokenError('BAD_CLAIMS');
      }

      const rawAmr = payload['amr'];
      const amr = Array.isArray(rawAmr)
        ? rawAmr.filter((v): v is string => typeof v === 'string')
        : ['pwd'];

      return {
        ...payload,
        sub,
        userId: sub,
        sid,
        sessionId: sid,
        jti: typeof payload.jti === 'string' ? payload.jti : '',
        amr,
        iss: String(payload.iss ?? env.JWT_ISSUER),
        aud: String(payload.aud ?? env.JWT_AUDIENCE),
        iat: Number(payload.iat ?? 0),
        exp: Number(payload.exp ?? 0),
      };
    } catch (err: unknown) {
      if (err instanceof InvalidTokenError) throw err;
      if (
        err instanceof errors.JWTExpired ||
        (err as { code?: string })?.code === 'ERR_JWT_EXPIRED' ||
        (err as { name?: string })?.name === 'JWTExpired'
      ) {
        throw new InvalidTokenError('EXPIRED');
      }
      if (
        err instanceof errors.JWTClaimValidationFailed ||
        (err as { code?: string })?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED'
      ) {
        throw new InvalidTokenError('BAD_CLAIMS');
      }
      throw new InvalidTokenError('BAD_SIGNATURE');
    }
  }
}
