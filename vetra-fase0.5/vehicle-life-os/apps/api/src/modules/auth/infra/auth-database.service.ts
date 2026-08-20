import { Injectable, Logger, type OnModuleDestroy } from '@nestjs/common';
import { Pool } from 'pg';
import type { PoolClient, PoolConfig, QueryResult, QueryResultRow } from 'pg';
import { getEnv } from '../../../config/env.js';

export type AuthExecutor = Pick<PoolClient, 'query'>;

/**
 * Pool exclusivo do modulo de autenticacao, conectado como `vlos_auth`
 * (Alternativa B, secao 4 do plano da Fase 1).
 *
 * vlos_auth nao tem privilegio sobre nenhuma tabela alem de identity.session e
 * identity.refresh_token, e e a unica role autorizada a executar as funcoes de
 * credencial. Consequencia pratica: uma SQL injection em qualquer outro modulo
 * do produto -- veiculos, eventos, documentos -- nao alcanca credencial alguma,
 * porque aquele codigo usa outro pool, com outra role.
 *
 * Este servico NAO expoe withUserContext: ele opera antes de existir identidade
 * provada. Tudo que acontece depois da autenticacao usa o DatabaseService comum,
 * sob RLS.
 */
@Injectable()
export class AuthDatabaseService implements OnModuleDestroy {
  private readonly logger = new Logger(AuthDatabaseService.name);
  private readonly pool: Pool;

  constructor() {
    const env = getEnv();
    const config: PoolConfig = {
      connectionString: env.DATABASE_AUTH_URL,
      max: env.DATABASE_AUTH_POOL_MAX,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      statement_timeout: 15_000,
      application_name: 'vlos-auth',
    };
    this.pool = new Pool(config);
    this.pool.on('error', (err: Error) => this.logger.error({ err }, 'erro no pool de autenticacao'));
  }

  async query<T extends QueryResultRow = QueryResultRow>(
    text: string,
    values: unknown[] = [],
  ): Promise<QueryResult<T>> {
    return this.pool.query<T>(text, values);
  }

  async transaction<T>(fn: (tx: AuthExecutor) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }
}
