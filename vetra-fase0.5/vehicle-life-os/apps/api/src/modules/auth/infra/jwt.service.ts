import { randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { SignJWT, decodeProtectedHeader, importPKCS8, importSPKI, jwtVerify } from 'jose';
import type { CryptoKey, KeyObject } from 'jose';
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
  iat: number;
  exp: number;
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

/**
 * Access token: JWT compacto, EdDSA (Ed25519), TTL curto, claims minimas.
 *
 * `algorithms: ['EdDSA']` na verificacao nao e detalhe: sem a lista explicita, um
 * token forjado com `alg: HS256` usando a CHAVE PUBLICA como segredo HMAC seria
 * aceito. E o ataque de confusao de algoritmo, e ha teste para ele.
 *
 * Nenhuma claim de autorizacao entra aqui. `admin_permission` e sempre consultada
 * no banco, sob RLS, a cada uso (item 24 do escopo).
 */
@Injectable()
export class JwtService {
  private readonly logger = new Logger(JwtService.name);
  private readonly keys: JwtKey[];
  private readonly privateKeys = new Map<string, CryptoKey | KeyObject>();
  private readonly publicKeys = new Map<string, CryptoKey | KeyObject>();

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

  private async privateKeyFor(key: JwtKey): Promise<CryptoKey | KeyObject> {
    const cached = this.privateKeys.get(key.kid);
    if (cached) return cached;
    const imported = await importPKCS8(key.privatePem, ALG);
    this.privateKeys.set(key.kid, imported);
    return imported;
  }

  private async publicKeyFor(key: JwtKey): Promise<CryptoKey | KeyObject> {
    const cached = this.publicKeys.get(key.kid);
    if (cached) return cached;
    const imported = await importSPKI(key.publicPem, ALG);
    this.publicKeys.set(key.kid, imported);
    return imported;
  }

  async sign(input: { userId: string; sessionId: string; amr: string[] }): Promise<{
    token: string;
    jti: string;
    expiresInSeconds: number;
  }> {
    const env = getEnv();
    const key = selectSigningKey(this.keys);
    const jti = randomUUID();

    const token = await new SignJWT({ sid: input.sessionId, amr: input.amr, jti })
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
      // kid nao e segredo: registrar ajuda a distinguir chave retirada cedo
      // demais de token forjado. A resposta ao cliente permanece generica.
      this.logger.warn({ kid: header.kid }, 'token com kid desconhecido');
      throw new InvalidTokenError('UNKNOWN_KID', typeof header.kid === 'string' ? header.kid : undefined);
    }

    try {
      const { payload } = await jwtVerify(token, await this.publicKeyFor(key), {
        algorithms: [ALG],
        issuer: env.JWT_ISSUER,
        audience: env.JWT_AUDIENCE,
      });

      const sid = payload['sid'];
      const amr = payload['amr'];
      if (typeof payload.sub !== 'string' || typeof sid !== 'string' || !Array.isArray(amr)) {
        throw new InvalidTokenError('BAD_CLAIMS');
      }

      return {
        sub: payload.sub,
        sid,
        jti: typeof payload.jti === 'string' ? payload.jti : '',
        amr: amr.filter((v): v is string => typeof v === 'string'),
        iss: String(payload.iss),
        aud: String(payload.aud),
        iat: Number(payload.iat),
        exp: Number(payload.exp),
      };
    } catch (err) {
      if (err instanceof InvalidTokenError) throw err;
      const code = (err as { code?: string }).code;
      if (code === 'ERR_JWT_EXPIRED') throw new InvalidTokenError('EXPIRED');
      if (code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') throw new InvalidTokenError('BAD_CLAIMS');
      throw new InvalidTokenError('BAD_SIGNATURE');
    }
  }
}
