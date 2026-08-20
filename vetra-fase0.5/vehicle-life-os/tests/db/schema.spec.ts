import { describe, it, expect } from 'vitest';
import { requireDatabase } from '../helpers/db.js';

describe('Database Schema & Foundation', () => {
  it('deve validar a integridade dos schemas e extensoes', async () => {
    const db = await requireDatabase();
    const res = await db.query(`
      SELECT schema_name FROM information_schema.schemata 
      WHERE schema_name IN ('identity', 'ops', 'audit');
    `);
    expect(res.rows.length).toBe(3);
  });
});
