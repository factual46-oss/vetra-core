import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type pg from 'pg';
import { APP_URL, HAS_DB, MIGRATOR_URL, asUser, connect, expectRejection } from '../helpers/db.js';

/**
 * REQUISITO DE SEGURANCA CRITICO (gate itens 7, 8, 9).
 *
 *   Usuario A NUNCA pode ler dado do usuario B --
 *   nem manipulando id, URL, parametro ou requisicao.
 *
 * Estes testes atacam a ultima linha de defesa: o proprio PostgreSQL, conectado
 * com a role da aplicacao. Se passarem aqui, um furo no controller ou uma SQL
 * injection ainda nao vazam dado de outro usuario.
 *
 * Na Fase 0 as unicas tabelas com dado de usuario sao identity.user e
 * identity.admin_permission. Na Fase 2, quando vehicle.vehicle existir, este
 * arquivo ganha os mesmos casos para veiculo, evento e documento -- a estrutura
 * ja esta pronta para isso.
 */
describe (!HAS_DB)('isolamento entre usuarios (RLS)', () => {
  let app: pg.Client;
  let migrator: pg.Client;
  let userA: string;
  let userB: string;
  let orgA: string;
  let orgB: string;

  beforeAll(async () => {
    app = connect(APP_URL!);
    migrator = connect(MIGRATOR_URL!);
    await app.connect();
    await migrator.connect();

    const oa = await migrator.query<{ id: string }>(
      `INSERT INTO identity.organization (legal_name, kind) VALUES ($1, 'WORKSHOP') RETURNING id`,
      [`Oficina A ${Date.now()}`],
    );
    const ob = await migrator.query<{ id: string }>(
      `INSERT INTO identity.organization (legal_name, kind) VALUES ($1, 'FLEET') RETURNING id`,
      [`Frota B ${Date.now()}`],
    );
    orgA = oa.rows[0]!.id;
    orgB = ob.rows[0]!.id;

    const a = await migrator.query<{ id: string }>(
      `INSERT INTO identity."user" (email, display_name, organization_id) VALUES ($1, $2, $3) RETURNING id`,
      [`a-${Date.now()}@teste.local`, 'Usuario A', orgA],
    );
    const b = await migrator.query<{ id: string }>(
      `INSERT INTO identity."user" (email, display_name, organization_id) VALUES ($1, $2, $3) RETURNING id`,
      [`b-${Date.now()}@teste.local`, 'Usuario B', orgB],
    );
    userA = a.rows[0]!.id;
    userB = b.rows[0]!.id;
  });

  afterAll(async () => {
    if (migrator) {
      await migrator.query(`DELETE FROM identity."user" WHERE id = ANY($1::uuid[])`, [[userA, userB]]);
      await migrator.query(`DELETE FROM identity.organization WHERE id = ANY($1::uuid[])`, [[orgA, orgB]]);
      await migrator.end();
    }
    if (app) await app.end();
  });

  it('A enxerga apenas o proprio registro', async () => {
    const result = await asUser(app, userA, `SELECT id FROM identity."user"`);
    expect(result.rows.map((r) => r.id)).toEqual([userA]);
  });

  it('A nao le o registro de B mesmo informando o id exato', async () => {
    const result = await asUser(app, userA, `SELECT id FROM identity."user" WHERE id = $1`, [userB]);
    expect(result.rowCount).toBe(0);
  });

  it('B nao le o registro de A (teste inverso)', async () => {
    const result = await asUser(app, userB, `SELECT id FROM identity."user" WHERE id = $1`, [userA]);
    expect(result.rowCount).toBe(0);
  });

  it('sem contexto de usuario, nenhuma linha e visivel (falha fechado)', async () => {
    const result = await asUser(app, null, `SELECT id FROM identity."user"`);
    expect(result.rowCount).toBe(0);
  });

  it('A nao altera o registro de B', async () => {
    const result = await asUser(app, userA, `UPDATE identity."user" SET display_name = $1 WHERE id = $2`, [
      'invadido',
      userB,
    ]);
    expect(result.rowCount).toBe(0);

    const check = await migrator.query<{ display_name: string }>(
      `SELECT display_name FROM identity."user" WHERE id = $1`,
      [userB],
    );
    expect(check.rows[0]!.display_name).toBe('Usuario B');
  });

  it('A nao consegue apagar nenhum registro: a role nao tem DELETE', async () => {
    const err = await expectRejection(() =>
      asUser(app, userA, `DELETE FROM identity."user" WHERE id = $1`, [userA]),
    );
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('a role da aplicacao nao executa DDL', async () => {
    const create = await expectRejection(() =>
      asUser(app, userA, `CREATE TABLE identity.tentativa_ddl (id int)`),
    );
    expect(create.message).toMatch(/permission denied|permissão negada/i);

    const drop = await expectRejection(() => asUser(app, userA, `DROP TABLE identity.admin_permission`));
    expect(drop.message).toMatch(/permission denied|must be owner|precisa ser|permissão negada/i);
  });

  it('a role da aplicacao nao escreve privilegio administrativo diretamente', async () => {
    const err = await expectRejection(() =>
      asUser(app, userA, `INSERT INTO identity.admin_permission (user_id, permission) VALUES ($1, $2)`, [
        userA,
        'admin:users',
      ]),
    );
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('conceder privilegio sem possuir admin:grant e recusado', async () => {
    const err = await expectRejection(() =>
      asUser(app, userA, `SELECT identity.grant_admin_permission($1, $2, $3)`, [
        userA,
        'admin:users',
        'tentativa de auto elevacao',
      ]),
    );
    expect(err.message).toMatch(/admin:grant/);
  });

  /**
   * AUD-22: identity.organization e entidade protegida por padrao.
   * A auditoria externa apontou que ela tinha ficado sem RLS -- e a guarda
   * ops.tables_missing_rls(), criada na 0006, teria apontado isso se tivesse
   * sido executada. Estes casos garantem que nao volte a acontecer em silencio.
   */
  it('5. A enxerga apenas a propria organizacao', async () => {
    const result = await asUser(app, userA, `SELECT id FROM identity.organization`);
    expect(result.rows.map((r) => r.id)).toEqual([orgA]);
  });

  it('5b. A nao acessa a organizacao de B mesmo informando o id exato', async () => {
    const result = await asUser(app, userA, `SELECT id, legal_name FROM identity.organization WHERE id = $1`, [
      orgB,
    ]);
    expect(result.rowCount).toBe(0);
  });

  it('5c. B nao acessa a organizacao de A (teste inverso)', async () => {
    const result = await asUser(app, userB, `SELECT id FROM identity.organization WHERE id = $1`, [orgA]);
    expect(result.rowCount).toBe(0);
  });

  it('sem contexto de usuario, nenhuma organizacao e visivel', async () => {
    const result = await asUser(app, null, `SELECT id FROM identity.organization`);
    expect(result.rowCount).toBe(0);
  });

  it('a aplicacao nao cria nem altera organizacao (sem policy de escrita)', async () => {
    // RLS sem policy de INSERT bloqueia a escrita mesmo com GRANT de tabela.
    // Onboarding de oficina sera funcao SECURITY DEFINER na Fase 2.
    const insert = await expectRejection(() =>
      asUser(app, userA, `INSERT INTO identity.organization (legal_name, kind) VALUES ('Pirata', 'WORKSHOP')`),
    );
    expect(insert.message).toMatch(/row-level security|violates row-level|seguranca em nivel/i);

    const update = await asUser(app, userA, `UPDATE identity.organization SET legal_name = $1 WHERE id = $2`, [
      'Renomeada',
      orgA,
    ]);
    expect(update.rowCount).toBe(0);
  });

  it('6. nao existe tabela de dado de usuario sem RLS', async () => {
    const result = await migrator.query(`SELECT * FROM ops.tables_missing_rls()`);
    expect(result.rows).toEqual([]);
  });
});
