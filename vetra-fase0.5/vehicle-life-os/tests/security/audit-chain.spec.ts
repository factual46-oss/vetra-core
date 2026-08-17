import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type pg from 'pg';
import { APP_URL, HAS_DB, MIGRATOR_URL, connect, expectRejection } from '../helpers/db.js';

/**
 * Gate itens 10 e 11, mais os achados AUD-23 da auditoria externa.
 *
 * A cadeia de hash prova duas coisas diferentes e igualmente importantes:
 *   1. em operacao normal a cadeia fecha;
 *   2. uma alteracao indevida E DETECTAVEL.
 *
 * E os privilegios provam uma terceira: a aplicacao escreve no log, mas nao o le
 * nem o altera.
 */
describe.skipIf(!HAS_DB)('cadeia de hash do log auditavel', () => {
  let db: pg.Client;
  let firstId: number;

  beforeAll(async () => {
    db = connect(MIGRATOR_URL!);
    await db.connect();
    const inserted = await db.query<{ id: string }>(
      `INSERT INTO audit.log (actor_type, action, metadata)
       VALUES ('SYSTEM', 'TEST_CHAIN_1', '{"n":1}'::jsonb),
              ('SYSTEM', 'TEST_CHAIN_2', '{"n":2}'::jsonb),
              ('SYSTEM', 'TEST_CHAIN_3', '{"n":3}'::jsonb)
       RETURNING id`,
    );
    firstId = Number(inserted.rows[0]!.id);
  });

  afterAll(async () => {
    if (db) await db.end();
  });

  it('sela cada entrada encadeando ao hash anterior', async () => {
    const rows = await db.query<{ id: string; prev_hash: Buffer | null; entry_hash: Buffer }>(
      `SELECT id, prev_hash, entry_hash FROM audit.log WHERE id >= $1 ORDER BY id`,
      [firstId],
    );
    expect(rows.rowCount).toBeGreaterThanOrEqual(3);
    for (let i = 1; i < rows.rows.length; i++) {
      expect(rows.rows[i]!.prev_hash?.toString('hex')).toBe(rows.rows[i - 1]!.entry_hash.toString('hex'));
    }
  });

  it('verify_chain nao aponta quebra em operacao normal', async () => {
    const result = await db.query(`SELECT * FROM audit.verify_chain()`);
    expect(result.rows).toEqual([]);
  });

  it('UPDATE e DELETE sao anulados pelas RULEs, inclusive para a dona da tabela', async () => {
    await db.query(`UPDATE audit.log SET action = 'ADULTERADO' WHERE id = $1`, [firstId]);
    await db.query(`DELETE FROM audit.log WHERE id = $1`, [firstId]);

    const check = await db.query<{ action: string }>(`SELECT action FROM audit.log WHERE id = $1`, [firstId]);
    expect(check.rowCount).toBe(1);
    expect(check.rows[0]!.action).toBe('TEST_CHAIN_1');
  });

  it('adulteracao com privilegio de dono e detectada pela verificacao', async () => {
    await db.query(`ALTER TABLE audit.log DISABLE RULE audit_log_no_update`);
    try {
      await db.query(`UPDATE audit.log SET metadata = '{"n":"adulterado"}'::jsonb WHERE id = $1`, [firstId]);

      const broken = await db.query<{ broken_at: string }>(`SELECT * FROM audit.verify_chain()`);
      expect(broken.rowCount).toBe(1);
      expect(Number(broken.rows[0]!.broken_at)).toBe(firstId);
    } finally {
      await db.query(`UPDATE audit.log SET metadata = '{"n":1}'::jsonb WHERE id = $1`, [firstId]);
      await db.query(`ALTER TABLE audit.log ENABLE RULE audit_log_no_update`);
    }

    const healed = await db.query(`SELECT * FROM audit.verify_chain()`);
    expect(healed.rows).toEqual([]);
  });
});

/**
 * AUD-23: a role da aplicacao escreve no log e nada mais.
 *
 * Estes quatro testes existem porque a expectativa arquitetural e verificavel:
 * "append-only para a aplicacao" ou e demonstravel contra o banco real, ou e
 * so uma frase no README.
 */
describe.skipIf(!HAS_DB)('privilegios da aplicacao sobre audit.log', () => {
  let app: pg.Client;
  let migrator: pg.Client;
  const marker = `TEST_APP_INSERT_${Date.now()}`;

  beforeAll(async () => {
    app = connect(APP_URL!);
    migrator = connect(MIGRATOR_URL!);
    await app.connect();
    await migrator.connect();
  });

  afterAll(async () => {
    if (app) await app.end();
    if (migrator) await migrator.end();
  });

  it('1. vlos_app CONSEGUE inserir no log auditavel', async () => {
    // sem RETURNING: nao ha policy de SELECT, e isso e deliberado
    await app.query(`INSERT INTO audit.log (actor_type, action) VALUES ('SYSTEM', $1)`, [marker]);

    // a confirmacao vem pela role dona, justamente porque a aplicacao nao le
    const check = await migrator.query(`SELECT 1 FROM audit.log WHERE action = $1`, [marker]);
    expect(check.rowCount).toBe(1);
  });

  it('o selo funciona mesmo sem SELECT para a aplicacao (trigger SECURITY DEFINER)', async () => {
    const row = await migrator.query<{ entry_hash: Buffer; prev_hash: Buffer | null }>(
      `SELECT entry_hash, prev_hash FROM audit.log WHERE action = $1`,
      [marker],
    );
    expect(row.rows[0]!.entry_hash).toBeInstanceOf(Buffer);
    expect(row.rows[0]!.prev_hash).not.toBeNull();

    const broken = await migrator.query(`SELECT * FROM audit.verify_chain()`);
    expect(broken.rows).toEqual([]);
  });

  it('2. vlos_app NAO consegue alterar o log auditavel', async () => {
    const err = await expectRejection(() =>
      app.query(`UPDATE audit.log SET action = 'ADULTERADO' WHERE action = $1`, [marker]),
    );
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('3. vlos_app NAO consegue apagar o log auditavel', async () => {
    const err = await expectRejection(() => app.query(`DELETE FROM audit.log WHERE action = $1`, [marker]));
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('4. vlos_app NAO consegue ler o log auditavel', async () => {
    const global = await expectRejection(() => app.query(`SELECT * FROM audit.log LIMIT 1`));
    expect(global.message).toMatch(/permission denied|permissão negada/i);

    // nem por linha especifica, nem por agregacao
    const targeted = await expectRejection(() =>
      app.query(`SELECT actor_user_id, reason FROM audit.log WHERE action = $1`, [marker]),
    );
    expect(targeted.message).toMatch(/permission denied|permissão negada/i);

    const counted = await expectRejection(() => app.query(`SELECT count(*) FROM audit.log`));
    expect(counted.message).toMatch(/permission denied|permissão negada/i);
  });

  it('INSERT ... RETURNING falha: nao ha caminho de leitura, nem indireto', async () => {
    const err = await expectRejection(() =>
      app.query(`INSERT INTO audit.log (actor_type, action) VALUES ('SYSTEM', 'X') RETURNING id`),
    );
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('a aplicacao nao calcula hashes: canonical_bytes nao e executavel por ela', async () => {
    const err = await expectRejection(() =>
      app.query(`SELECT audit.canonical_bytes(now(), 'SYSTEM', NULL, 'X', NULL, NULL, NULL, '{}'::jsonb)`),
    );
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('vlos_app nao le as ancoras da cadeia', async () => {
    const err = await expectRejection(() => app.query(`SELECT * FROM audit.chain_anchor LIMIT 1`));
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });
});
