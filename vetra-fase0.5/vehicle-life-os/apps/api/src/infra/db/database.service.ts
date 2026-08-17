import { Injectable, Logger, type OnModuleDestroy } from '@nestjs/common';
import pg from 'pg';
import { getEnv } from '../../config/env.js';

export type Executor = Pick<pg.PoolClient, 'query'>;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Acesso ao PostgreSQL.
 *
 * Regra central (Doc 02, secao 12): toda transacao que toca dado de usuario roda
 * dentro de withUserContext(), que define app.user_id. As policies de RLS
 * dependem disso; sem o set_config, o banco devolve zero linhas -- que e
 * exatamente o comportamento desejado quando alguem esquece o helper.
 *
 * A conexao usa vlos_app: sem BYPASSRLS, sem DDL, sem DELETE.
 */
@Injectable()
export class DatabaseService implements OnModuleDestroy {
  private readonly logger = new Logger(DatabaseService.name);
  private readonly pool: pg.Pool;

  constructor() {
    const env = getEnv();
    this.pool = new pg.Pool({
      connectionString: env.DATABASE_URL,
      max: env.DATABASE_POOL_MAX,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      statement_timeout: 15_000, // AUD-13: consulta travada nao segura conexao do pool
      application_name: 'vlos-api',
    });
    this.pool.on('error', (err) => this.logger.error({ err }, 'erro no pool do postgres'));
  }

  /**
   * Transacao com identidade do usuario. Este e o metodo padrao -- os
   * "unscoped" abaixo sao a excecao, e o nome existe justamente para que a
   * excecao apareca no code review.
   *
   * set_config(..., is_local => true) vale ate o fim da transacao e nao vaza
   * para a proxima requisicao que reutilizar a conexao do pool.
   */
  async withUserContext<T>(userId: string, fn: (tx: Executor) => Promise<T>): Promise<T> {
    // AUD-11: validar o formato antes de chegar ao banco. Nao ha injecao possivel
    // (set_config e parametrizado), mas um valor invalido faria o cast da policy
    // estourar em runtime, transformando erro de autenticacao em erro 500.
    if (!UUID_RE.test(userId)) {
      throw new Error('withUserContext exige um UUID valido');
    }

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT set_config($1, $2, true)', ['app.user_id', userId]);
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

  /**
   * Consulta SEM contexto de usuario -- portanto sem RLS de usuario.
   * Uso legitimo: health check, catalogo publico, tarefas de sistema.
   * Nunca use para ler dado pertencente a um usuario.
   */
  async queryUnscoped<T extends pg.QueryResultRow = pg.QueryResultRow>(
    text: string,
    values: unknown[] = [],
  ): Promise<pg.QueryResult<T>> {
    return this.pool.query<T>(text, values);
  }

  /** Transacao sem contexto de usuario. Mesma advertencia de queryUnscoped. */
  async transactionUnscoped<T>(fn: (tx: Executor) => Promise<T>): Promise<T> {
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

  async ping(): Promise<void> {
    await this.pool.query('SELECT 1');
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }
}
