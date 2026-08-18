import pg from 'pg';

/*
 * Conexoes usadas pelos testes de banco.
 *
 * TEST_DATABASE_URL_APP      -> role vlos_app      (a que a API usa)
 * TEST_DATABASE_URL_MIGRATOR -> role vlos_migrator (dona, prepara fixtures)
 *
 * Quando as variaveis nao existem, as suites sao PULADAS e o vitest mostra
 * "skipped" -- nunca "passed". Teste de seguranca que passa sem rodar e pior
 * que teste nenhum, porque cria confianca falsa.
 */
export const APP_URL = process.env.TEST_DATABASE_URL_APP;
export const MIGRATOR_URL = process.env.TEST_DATABASE_URL_MIGRATOR;
export const HAS_DB = Boolean(APP_URL && MIGRATOR_URL);

export function connect(url: string): pg.Client {
  return new pg.Client({ connectionString: url });
}

/** Executa uma consulta como vlos_app dentro de um contexto de usuario. */
export async function asUser<T extends pg.QueryResultRow = pg.QueryResultRow>(
  client: pg.Client,
  userId: string | null,
  sql: string,
  values: unknown[] = [],
): Promise<pg.QueryResult<T>> {
  await client.query('BEGIN');
  try {
    if (userId !== null) {
      await client.query('SELECT set_config($1, $2, true)', ['app.user_id', userId]);
    }
    const result = await client.query<T>(sql, values);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  }
}

export async function expectRejection(fn: () => Promise<unknown>): Promise<Error> {
  try {
    await fn();
  } catch (err) {
    return err as Error;
  }
  throw new Error('esperava rejeicao, mas a operacao foi permitida');
}
