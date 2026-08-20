import { randomUUID } from 'node:crypto';
import { Client } from 'pg';
import { MIGRATOR_URL, connect } from './db.js';

/**
 * As suites da Fase 1 nao usam skipIf. Sem banco configurado elas falham aqui,
 * com mensagem clara -- SKIP nao e PASS (item 3 do escopo da Fase 1).
 */
export function requireDatabase(): { app: string; auth: string; migrator: string } {
  const app = process.env['TEST_DATABASE_URL_APP'];
  const auth = process.env['TEST_DATABASE_URL_AUTH'];
  const migrator = process.env['TEST_DATABASE_URL_MIGRATOR'];
  if (!app || !auth || !migrator) {
    throw new Error(
      'Faltam TEST_DATABASE_URL_APP, TEST_DATABASE_URL_AUTH e TEST_DATABASE_URL_MIGRATOR. ' +
        'As suites da Fase 1 exigem PostgreSQL real.',
    );
  }
  return { app, auth, migrator };
}

export function uniqueEmail(prefix = 'u'): string {
  return `${prefix}-${randomUUID()}@teste.local`;
}

/** Limpa tudo que a suite criou, pela role dona. */
export async function cleanupUsers(userIds: readonly string[]): Promise<void> {
  if (userIds.length === 0) return;
  const db: Client = connect(MIGRATOR_URL!);
  await db.connect();
  try {
    await db.query(`DELETE FROM identity."user" WHERE id = ANY($1::uuid[])`, [userIds]);
  } finally {
    await db.end();
  }
}

export async function withMigrator<T>(fn: (db: Client) => Promise<T>): Promise<T> {
  const db: Client = connect(MIGRATOR_URL!);
  await db.connect();
  try {
    return await fn(db);
  } finally {
    await db.end();
  }
}

export const testSignals = { ip: '203.0.113.10', userAgent: 'vitest', requestId: 'test-request' };
