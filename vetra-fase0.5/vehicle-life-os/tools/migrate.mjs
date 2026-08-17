#!/usr/bin/env node
/**
 * Runner de migrations.
 *
 * Decisoes:
 *  - SQL puro versionado, nao DSL de ORM. RLS, triggers, rules e policies
 *    precisam ser lidos e revisados como SQL.
 *  - Cada arquivo roda UMA vez, dentro de UMA transacao, com checksum gravado.
 *    Arquivo ja aplicado que muda de conteudo = erro, nao reaplicacao silenciosa.
 *  - Advisory lock global: dois deploys simultaneos nao corrompem o estado.
 *  - Conecta com DATABASE_MIGRATION_URL (role dona), nunca com a role da API.
 */
import { readdir, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MIGRATIONS_DIR = join(ROOT, 'db', 'migrations');
const SEEDS_DIR = join(ROOT, 'db', 'seeds');
const LOCK_ID = 918273645;

const url = process.env.DATABASE_MIGRATION_URL ?? process.env.DATABASE_URL;
if (!url) {
  console.error('DATABASE_MIGRATION_URL nao definida.');
  process.exit(1);
}

const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const log = (...a) => console.log('[migrate]', ...a);

async function listSql(dir) {
  const files = await readdir(dir).catch(() => []);
  return files.filter((f) => f.endsWith('.sql')).sort();
}

async function ensureBookkeeping(client) {
  await client.query(`
    CREATE SCHEMA IF NOT EXISTS _meta;
    CREATE TABLE IF NOT EXISTS _meta.migration (
      filename    text PRIMARY KEY,
      checksum    text NOT NULL,
      applied_at  timestamptz NOT NULL DEFAULT now(),
      duration_ms integer NOT NULL
    );
  `);
}

async function up(client) {
  const applied = new Map(
    (await client.query('SELECT filename, checksum FROM _meta.migration')).rows.map((r) => [
      r.filename,
      r.checksum,
    ]),
  );

  let count = 0;
  for (const file of await listSql(MIGRATIONS_DIR)) {
    const sql = await readFile(join(MIGRATIONS_DIR, file), 'utf8');
    const checksum = sha256(sql);
    const known = applied.get(file);

    if (known === checksum) continue;
    if (known && known !== checksum) {
      throw new Error(
        `Migration ja aplicada foi alterada: ${file}\n` +
          `Migrations sao imutaveis. Crie um novo arquivo com a correcao.`,
      );
    }

    const started = Date.now();
    await client.query('BEGIN');
    try {
      await client.query(sql);
      await client.query(
        'INSERT INTO _meta.migration (filename, checksum, duration_ms) VALUES ($1, $2, $3)',
        [file, checksum, Date.now() - started],
      );
      await client.query('COMMIT');
      log(`aplicada ${file} (${Date.now() - started}ms)`);
      count++;
    } catch (err) {
      await client.query('ROLLBACK');
      throw new Error(`Falha em ${file}: ${err.message}`);
    }
  }
  log(count === 0 ? 'nada a aplicar' : `${count} migration(s) aplicada(s)`);
}

async function seed(client) {
  for (const file of await listSql(SEEDS_DIR)) {
    const sql = await readFile(join(SEEDS_DIR, file), 'utf8');
    await client.query('BEGIN');
    try {
      await client.query(sql);
      await client.query('COMMIT');
      log(`seed ${file}`);
    } catch (err) {
      await client.query('ROLLBACK');
      throw new Error(`Falha no seed ${file}: ${err.message}`);
    }
  }
}

async function status(client) {
  await ensureBookkeeping(client);
  const applied = new Set(
    (await client.query('SELECT filename FROM _meta.migration')).rows.map((r) => r.filename),
  );
  for (const file of await listSql(MIGRATIONS_DIR)) {
    console.log(`${applied.has(file) ? '  aplicada ' : '  PENDENTE '} ${file}`);
  }
}

const client = new pg.Client({ connectionString: url });
await client.connect();
try {
  const cmd = process.argv[2] ?? 'up';
  if (cmd === 'status') {
    await status(client);
  } else {
    await client.query('SELECT pg_advisory_lock($1)', [LOCK_ID]);
    await ensureBookkeeping(client);
    if (cmd === 'up') await up(client);
    else if (cmd === 'seed') await seed(client);
    else throw new Error(`Comando desconhecido: ${cmd}. Use up | seed | status.`);
    await client.query('SELECT pg_advisory_unlock($1)', [LOCK_ID]);
  }
} catch (err) {
  console.error('[migrate] ERRO:', err.message);
  process.exitCode = 1;
} finally {
  await client.end();
}
