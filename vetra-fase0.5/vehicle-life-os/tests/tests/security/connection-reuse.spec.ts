import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DatabaseService } from '../../apps/api/src/infra/db/database.service.js';
import { cleanupUsers, requireDatabase, uniqueEmail, withMigrator } from '../helpers/auth.js';

/**
 * ITEM 29 DO ESCOPO -- o teste que protege contra a regressao mais silenciosa
 * possivel: trocar `set_config(..., is_local => true)` por um SET de sessao.
 *
 * Com `DATABASE_POOL_MAX = 1` ha UMA conexao fisica, garantidamente reutilizada
 * entre as transacoes. Se o contexto vazasse de uma transacao para a proxima,
 * o usuario B enxergaria dados de A -- e e exatamente isso que medimos.
 */
process.env['DATABASE_POOL_MAX'] = '1';
requireDatabase();

describe('reutilizacao de conexao nao vaza contexto de usuario', () => {
  let db: DatabaseService;
  let userA: string;
  let userB: string;

  beforeAll(async () => {
    db = new DatabaseService();
    const ids = await withMigrator(async (m) => {
      const a = await m.query<{ id: string }>(
        `INSERT INTO identity."user" (email, display_name) VALUES ($1, 'A') RETURNING id`, [uniqueEmail('cra')]);
      const b = await m.query<{ id: string }>(
        `INSERT INTO identity."user" (email, display_name) VALUES ($1, 'B') RETURNING id`, [uniqueEmail('crb')]);
      return [a.rows[0]!.id, b.rows[0]!.id];
    });
    userA = ids[0]!;
    userB = ids[1]!;
  });

  afterAll(async () => {
    await cleanupUsers([userA, userB]);
    await db.onModuleDestroy();
  });

  it('1. COMMIT de A e depois consulta de B: B enxerga apenas B', async () => {
    const seenByA = await db.withUserContext(userA, async (tx) => {
      const r = await tx.query<{ id: string }>(`SELECT id FROM identity."user"`);
      return r.rows.map((x) => x.id);
    });
    expect(seenByA).toEqual([userA]);

    const seenByB = await db.withUserContext(userB, async (tx) => {
      const r = await tx.query<{ id: string }>(`SELECT id FROM identity."user"`);
      return r.rows.map((x) => x.id);
    });
    expect(seenByB).toEqual([userB]);
  });

  it('2. ROLLBACK de A nao deixa contexto para B', async () => {
    await expect(
      db.withUserContext(userA, async (tx) => {
        await tx.query(`SELECT id FROM identity."user"`);
        throw new Error('erro proposital');
      }),
    ).rejects.toThrow('erro proposital');

    const seenByB = await db.withUserContext(userB, async (tx) => {
      const r = await tx.query<{ id: string }>(`SELECT id FROM identity."user"`);
      return r.rows.map((x) => x.id);
    });
    expect(seenByB).toEqual([userB]);
  });

  it('3. apos qualquer transacao, consulta sem contexto nao enxerga nada', async () => {
    await db.withUserContext(userA, async (tx) => {
      await tx.query(`SELECT id FROM identity."user"`);
    });

    const semContexto = await db.transactionUnscoped(async (tx) => {
      const r = await tx.query(`SELECT id FROM identity."user"`);
      return r.rowCount;
    });
    expect(semContexto).toBe(0);
  });
});
