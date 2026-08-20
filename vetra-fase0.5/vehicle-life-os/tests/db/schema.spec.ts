import { describe, it, expect } from 'vitest';
import pg from 'pg';

describe('Database Schema & Foundation', () => {
  it('deve validar a integridade dos schemas e extensoes', async () => {
    const connectionString =
      process.env.TEST_DATABASE_URL_MIGRATOR ||
      process.env.DATABASE_URL ||
      'postgres://vlos_migrator:vetra_password@localhost:5432/vetra_test';

    const client = new pg.Client({ connectionString });
    await client.connect();

    try {
      const res = await client.query(`
        SELECT schema_name FROM information_schema.schemata 
        WHERE schema_name IN ('identity', 'ops', 'audit');
      `);
      expect(res.rows.length).toBe(3);
    } finally {
      await client.end();
    }
  });
});
