import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from 'pg';
import { APP_URL, MIGRATOR_URL, connect, expectRejection } from '../helpers/db.js';
import { requireDatabase } from '../helpers/auth.js';

/**
 * Alternativa B (secao 4 do plano), provada contra o banco.
 *
 * A afirmacao que estes testes sustentam e exatamente esta, sem exagero:
 * a role generica da aplicacao -- a que todo o produto futuro vai usar para
 * veiculos, eventos e documentos -- NAO alcanca credencial nenhuma.
 */
requireDatabase();

describe('segregacao de privilegios entre vlos_app e vlos_auth', () => {
  let app: Client;
  let auth: Client;
  let migrator: Client;

  beforeAll(async () => {
    const urls = requireDatabase();
    app = connect(APP_URL!);
    auth = connect(urls.auth);
    migrator = connect(MIGRATOR_URL!);
    await Promise.all([app.connect(), auth.connect(), migrator.connect()]);
  });

  afterAll(async () => {
    await Promise.all([app.end(), auth.end(), migrator.end()]);
  });

  it('vlos_app NAO le identity.credential', async () => {
    const err = await expectRejection(() => app.query(`SELECT * FROM identity.credential LIMIT 1`));
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('vlos_app NAO escreve em identity.credential', async () => {
    const err = await expectRejection(() =>
      app.query(`INSERT INTO identity.credential (user_id, password_hash, params) VALUES (gen_random_uuid(), 'x', '{}')`),
    );
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('vlos_app NAO executa authenticate_lookup', async () => {
    const err = await expectRejection(() => app.query(`SELECT * FROM identity.authenticate_lookup('a@b.com')`));
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('vlos_app NAO executa register_user', async () => {
    const err = await expectRejection(() =>
      app.query(`SELECT identity.register_user('x@y.com', 'N', 'hash-suficientemente-longo', '{}'::jsonb)`),
    );
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('vlos_app NAO executa set_password', async () => {
    const err = await expectRejection(() =>
      app.query(`SELECT identity.set_password(gen_random_uuid(), 'hash-suficientemente-longo', '{}'::jsonb, false)`),
    );
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('vlos_app NAO le identity.refresh_token', async () => {
    const err = await expectRejection(() => app.query(`SELECT * FROM identity.refresh_token LIMIT 1`));
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('vlos_auth tambem NAO le identity.credential diretamente', async () => {
    // A credencial e alcancavel apenas pelas funcoes SECURITY DEFINER --
    // nem a role de autenticacao tem acesso a tabela.
    const err = await expectRejection(() => auth.query(`SELECT * FROM identity.credential LIMIT 1`));
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('vlos_auth NAO le o log auditavel', async () => {
    const err = await expectRejection(() => auth.query(`SELECT * FROM audit.log LIMIT 1`));
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('vlos_auth NAO le dados de veiculo nem de usuario alheios ao seu escopo', async () => {
    const err = await expectRejection(() => auth.query(`SELECT * FROM identity."user" LIMIT 1`));
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('vlos_auth NAO executa DDL', async () => {
    const err = await expectRejection(() => auth.query(`CREATE TABLE identity.tentativa (id int)`));
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('nenhuma role de aplicacao tem BYPASSRLS', async () => {
    const r = await migrator.query<{ rolname: string }>(
      `SELECT rolname FROM pg_roles WHERE rolname IN ('vlos_app','vlos_auth') AND rolbypassrls`,
    );
    expect(r.rows).toEqual([]);
  });

  it('nenhuma role de aplicacao e dona de tabela', async () => {
    const r = await migrator.query(
      `SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
        WHERE r.rolname IN ('vlos_app','vlos_auth') AND c.relkind = 'r'`,
    );
    expect(r.rowCount).toBe(0);
  });

  it('a guarda de RLS continua limpa com as tabelas da Fase 1A', async () => {
    const r = await migrator.query(`SELECT * FROM ops.tables_missing_rls()`);
    expect(r.rows).toEqual([]);
  });

  it('as tres tabelas novas estao sob RLS', async () => {
    const r = await migrator.query<{ relname: string }>(
      `SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'identity' AND c.relrowsecurity
          AND relname IN ('credential','session','refresh_token')
        ORDER BY relname`,
    );
    expect(r.rows.map((x) => x.relname)).toEqual(['credential', 'refresh_token', 'session']);
  });
});
