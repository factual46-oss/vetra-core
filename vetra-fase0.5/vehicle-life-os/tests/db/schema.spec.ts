import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from 'pg';
import { HAS_DB, MIGRATOR_URL, connect, expectRejection } from '../helpers/db.js';

/** Gate itens 41 e 42: integridade referencial, constraints, transacoes, migrations. */
describe.skipIf(!HAS_DB)('integridade do schema', () => {
  let db: Client;

  beforeAll(async () => {
    db = connect(MIGRATOR_URL!);
    await db.connect();
  });

  afterAll(async () => {
    if (db) await db.end();
  });

  it('aplicou todas as migrations do diretorio', async () => {
    const result = await db.query<{ filename: string }>(
      `SELECT filename FROM _meta.migration ORDER BY filename`,
    );
    const applied = result.rows.map((r) => r.filename);
    expect(applied).toContain('0001_foundation.sql');
    expect(applied).toContain('0006_rls_pattern.sql');
  });

  it('recusa chave estrangeira invalida', async () => {
    const err = await expectRejection(() =>
      db.query(`INSERT INTO identity.admin_permission (user_id, permission) VALUES (gen_random_uuid(), 'x')`),
    );
    expect(err.message).toMatch(/foreign key|chave estrangeira/i);
  });

  it('recusa e-mail duplicado entre contas vivas', async () => {
    const email = `dup-${Date.now()}@teste.local`;
    const created = await db.query<{ id: string }>(
      `INSERT INTO identity."user" (email, display_name) VALUES ($1, 'A') RETURNING id`,
      [email],
    );
    try {
      const err = await expectRejection(() =>
        db.query(`INSERT INTO identity."user" (email, display_name) VALUES ($1, 'B')`, [email]),
      );
      expect(err.message).toMatch(/duplicate key|duplicada/i);
    } finally {
      await db.query(`DELETE FROM identity."user" WHERE id = $1`, [created.rows[0]!.id]);
    }
  });

  it('permite reuso do e-mail apos exclusao logica', async () => {
    const email = `soft-${Date.now()}@teste.local`;
    const first = await db.query<{ id: string }>(
      `INSERT INTO identity."user" (email, display_name) VALUES ($1, 'A') RETURNING id`,
      [email],
    );
    await db.query(`UPDATE identity."user" SET deleted_at = now() WHERE id = $1`, [first.rows[0]!.id]);

    const second = await db.query<{ id: string }>(
      `INSERT INTO identity."user" (email, display_name) VALUES ($1, 'B') RETURNING id`,
      [email],
    );
    expect(second.rowCount).toBe(1);

    await db.query(`DELETE FROM identity."user" WHERE id = ANY($1::uuid[])`, [
      [first.rows[0]!.id, second.rows[0]!.id],
    ]);
  });

  it('faz rollback completo da transacao', async () => {
    const email = `rb-${Date.now()}@teste.local`;
    await db.query('BEGIN');
    await db.query(`INSERT INTO identity."user" (email, display_name) VALUES ($1, 'temp')`, [email]);
    await db.query('ROLLBACK');

    const result = await db.query(`SELECT 1 FROM identity."user" WHERE email = $1`, [email]);
    expect(result.rowCount).toBe(0);
  });

  it('atualiza updated_at por trigger', async () => {
    const created = await db.query<{ id: string; updated_at: Date }>(
      `INSERT INTO identity."user" (email, display_name) VALUES ($1, 'A') RETURNING id, updated_at`,
      [`touch-${Date.now()}@teste.local`],
    );
    const id = created.rows[0]!.id;
    await new Promise((r) => setTimeout(r, 10));
    const updated = await db.query<{ updated_at: Date }>(
      `UPDATE identity."user" SET display_name = 'B' WHERE id = $1 RETURNING updated_at`,
      [id],
    );
    expect(updated.rows[0]!.updated_at.getTime()).toBeGreaterThan(created.rows[0]!.updated_at.getTime());
    await db.query(`DELETE FROM identity."user" WHERE id = $1`, [id]);
  });

  it('mantem o catalogo de tipos de evento carregado pelo seed', async () => {
    const result = await db.query<{ count: string }>(
      `SELECT count(*) FROM vehicle.event_type WHERE is_active`,
    );
    expect(Number(result.rows[0]!.count)).toBeGreaterThanOrEqual(24);
  });
});
