import { Injectable } from '@nestjs/common';
import type { Argon2Params } from './password-hasher.service.js';
import { AuthDatabaseService } from './auth-database.service.js';

export interface CredentialLookup {
  userId: string;
  passwordHash: string;
  algorithm: string;
  params: Argon2Params | null;
  isBlocked: boolean;
  emailVerified: boolean;
}

export class EmailAlreadyRegisteredError extends Error {
  constructor() {
    super('e-mail ja cadastrado');
    this.name = 'EmailAlreadyRegisteredError';
  }
}

const UNIQUE_VIOLATION = '23505';

/**
 * Unico caminho ate identity.credential. A tabela nao tem policy nem grant para
 * nenhuma role de aplicacao: so as funcoes SECURITY DEFINER a enxergam, e so
 * `vlos_auth` pode executa-las.
 */
@Injectable()
export class CredentialRepository {
  constructor(private readonly db: AuthDatabaseService) {}

  async register(input: {
    email: string;
    displayName: string;
    passwordHash: string;
    params: Argon2Params;
  }): Promise<string> {
    try {
      const result = await this.db.query<{ register_user: string }>(
        `SELECT identity.register_user($1, $2, $3, $4::jsonb) AS register_user`,
        [input.email, input.displayName, input.passwordHash, JSON.stringify(input.params)],
      );
      return result.rows[0]!.register_user;
    } catch (err) {
      if ((err as { code?: string }).code === UNIQUE_VIOLATION) {
        throw new EmailAlreadyRegisteredError();
      }
      throw err;
    }
  }

  async lookup(email: string): Promise<CredentialLookup | null> {
    const result = await this.db.query<{
      user_id: string;
      password_hash: string;
      algorithm: string;
      params: Argon2Params | null;
      is_blocked: boolean;
      email_verified: boolean;
    }>(`SELECT * FROM identity.authenticate_lookup($1)`, [email]);

    const row = result.rows[0];
    if (!row) return null;

    return {
      userId: row.user_id,
      passwordHash: row.password_hash,
      algorithm: row.algorithm,
      params: row.params,
      isBlocked: row.is_blocked,
      emailVerified: row.email_verified,
    };
  }

  async setPassword(input: {
    userId: string;
    passwordHash: string;
    params: Argon2Params;
    rehashOnly: boolean;
  }): Promise<void> {
    await this.db.query(`SELECT identity.set_password($1, $2, $3::jsonb, $4)`, [
      input.userId,
      input.passwordHash,
      JSON.stringify(input.params),
      input.rehashOnly,
    ]);
  }
}
