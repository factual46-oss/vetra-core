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

/**
 * FASE 1B — BLOCO 1
 *
 * A guarda de privilegios da 0010 vivia num bloco DO: rodou uma vez e virou
 * documentacao. A 0015 a transformou em funcao, e estes testes sao o que a
 * mantem viva -- eles rodam a cada pipeline, nao uma vez na historia do banco.
 */
describe('guarda permanente de privilegios (Fase 1B)', () => {
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

  it('nao existe privilegio concedido fora da lista branca', async () => {
    const r = await migrator.query(`SELECT * FROM ops.unexpected_privileges()`);
    // Se falhar, a saida abaixo diz exatamente o que sobra.
    expect(r.rows).toEqual([]);
  });

  it('nao existe privilegio declarado que nao exista de fato', async () => {
    // Pega erro de digitacao na lista e revogacao feita sem atualizar a declaracao.
    const r = await migrator.query(`SELECT * FROM ops.missing_privileges()`);
    expect(r.rows).toEqual([]);
  });

  it('a guarda enxerga EXECUTE de funcao, e nao apenas privilegio de tabela', async () => {
    // A versao anterior consultava information_schema.table_privileges e seria
    // cega justamente para os GRANT EXECUTE que a Fase 1B cria.
    const r = await migrator.query<{ n: string }>(
      `SELECT count(*) AS n FROM ops.privilege_snapshot() WHERE object_type = 'FUNCTION'`,
    );
    expect(Number(r.rows[0]!.n)).toBeGreaterThan(0);
  });

  it('a guarda cobre as quatro classes de objeto', async () => {
    const r = await migrator.query<{ object_type: string }>(
      `SELECT DISTINCT object_type FROM ops.privilege_snapshot() ORDER BY 1`,
    );
    const tipos = r.rows.map((x) => x.object_type);
    expect(tipos).toContain('TABLE');
    expect(tipos).toContain('FUNCTION');
    expect(tipos).toContain('SCHEMA');
  });

  it('nenhuma funcao propria continua executavel por PUBLIC', async () => {
    // aclexplode(NULL) devolve zero linhas: funcao nunca tocada tem acl NULL e
    // EXECUTE para PUBLIC por padrao. O snapshot materializa esse padrao com
    // acldefault, entao esta assercao so passa se os REVOKE existirem de fato.
    // Era exatamente o defeito da 0011 (canonical_bytes via PUBLIC).
    const r = await migrator.query(
      `SELECT * FROM ops.privilege_snapshot()
        WHERE grantee = 'PUBLIC' AND object_type = 'FUNCTION'`,
    );
    expect(r.rows).toEqual([]);
  });
});

describe('tabelas da Fase 1B: RLS e privilegio minimo', () => {
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

  it.each(['single_use_token', 'mfa_totp', 'recovery_code', 'mfa_challenge'])(
    'identity.%s esta sob RLS',
    async (tabela) => {
      const r = await migrator.query<{ relrowsecurity: boolean }>(
        `SELECT c.relrowsecurity FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'identity' AND c.relname = $1`,
        [tabela],
      );
      expect(r.rows[0]!.relrowsecurity).toBe(true);
    },
  );

  it.each(['single_use_token', 'mfa_totp', 'recovery_code', 'mfa_challenge'])(
    'vlos_app NAO le identity.%s',
    async (tabela) => {
      // A armadilha da 0005 concede SELECT/INSERT/UPDATE a vlos_app em toda
      // tabela nova de identity. Sem os REVOKE da 0013, estes testes falham.
      const err = await expectRejection(() => app.query(`SELECT * FROM identity.${tabela} LIMIT 1`));
      expect(err.message).toMatch(/permission denied|permissão negada/i);
    },
  );

  it('vlos_auth NAO le identity.single_use_token: so as funcoes definer acessam', async () => {
    const err = await expectRejection(() => auth.query(`SELECT * FROM identity.single_use_token LIMIT 1`));
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });

  it('vlos_app NAO executa as funcoes de token de uso unico', async () => {
    const consume = await expectRejection(() =>
      app.query(`SELECT identity.consume_single_use_token('PASSWORD_RESET', extensions.digest('x','sha256'))`),
    );
    expect(consume.message).toMatch(/permission denied|permissão negada/i);

    const issue = await expectRejection(() =>
      app.query(`SELECT identity.issue_single_use_token(gen_random_uuid(), 'PASSWORD_RESET', extensions.digest('x','sha256'), 30)`),
    );
    expect(issue.message).toMatch(/permission denied|permissão negada/i);
  });

  it('identity.mfa_totp aceita no maximo uma configuracao por usuario', async () => {
    // Multiplas configuracoes pendentes simultaneas sao impossiveis por
    // construcao: user_id e a chave primaria.
    const r = await migrator.query<{ n: string }>(
      `SELECT count(*) AS n FROM pg_index i
         JOIN pg_class c ON c.oid = i.indrelid
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE ns.nspname = 'identity' AND c.relname = 'mfa_totp' AND i.indisprimary`,
    );
    expect(Number(r.rows[0]!.n)).toBe(1);
  });

  it('identity.session ganhou reauthenticated_at sem alterar as colunas existentes', async () => {
    const r = await migrator.query<{ column_name: string; is_nullable: string }>(
      `SELECT column_name, is_nullable FROM information_schema.columns
        WHERE table_schema = 'identity' AND table_name = 'session'
          AND column_name = 'reauthenticated_at'`,
    );
    expect(r.rowCount).toBe(1);
    // Anulavel e sem default: nenhuma consulta existente muda de resultado.
    expect(r.rows[0]!.is_nullable).toBe('YES');
  });

  it('a guarda de RLS continua limpa com as quatro tabelas novas', async () => {
    const r = await migrator.query(`SELECT * FROM ops.tables_missing_rls()`);
    expect(r.rows).toEqual([]);
  });
});

/**
 * BLOCO 3.5 — vlos_app perdeu a mutacao em identity.session.
 *
 * A janela de reautenticacao mora numa coluna dessa tabela. Com UPDATE de
 * tabela, a policy restringia a linha mas nao a coluna: uma injecao em qualquer
 * modulo do produto poderia abrir a janela da propria sessao e, com um token
 * roubado, desativar o segundo fator.
 */
describe('vlos_app sem mutacao em identity.session (Bloco 3.5)', () => {
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

  it('vlos_app NAO tem privilegio de UPDATE em identity.session', async () => {
    const r = await migrator.query<{ pode: boolean }>(
      `SELECT has_table_privilege('vlos_app', 'identity.session', 'UPDATE') AS pode`,
    );
    expect(r.rows[0]!.pode).toBe(false);
  });

  it('vlos_app MANTEM SELECT: a verificacao de sessao por requisicao depende dela', async () => {
    const r = await migrator.query<{ pode: boolean }>(
      `SELECT has_table_privilege('vlos_app', 'identity.session', 'SELECT') AS pode`,
    );
    expect(r.rows[0]!.pode).toBe(true);
  });

  it('vlos_auth continua podendo escrever em identity.session', async () => {
    const r = await migrator.query<{ pode: boolean }>(
      `SELECT has_table_privilege('vlos_auth', 'identity.session', 'UPDATE') AS pode`,
    );
    expect(r.rows[0]!.pode).toBe(true);
  });

  it('a policy session_self_update foi removida junto com o privilegio', async () => {
    // Deixa-la sem privilegio correspondente faria alguem ler o schema no
    // futuro e concluir que vlos_app escreve em sessoes.
    const r = await migrator.query(
      `SELECT 1 FROM pg_policies WHERE schemaname = 'identity' AND tablename = 'session'
        AND policyname = 'session_self_update'`,
    );
    expect(r.rowCount).toBe(0);
  });

  it('a lista branca reflete a revogacao nas duas direcoes', async () => {
    const declarado = await migrator.query(
      `SELECT 1 FROM ops.privilege_allowlist
        WHERE grantee = 'vlos_app' AND object_name = 'identity.session' AND privilege = 'UPDATE'`,
    );
    expect(declarado.rowCount).toBe(0);

    expect((await migrator.query(`SELECT * FROM ops.unexpected_privileges()`)).rows).toEqual([]);
    expect((await migrator.query(`SELECT * FROM ops.missing_privileges()`)).rows).toEqual([]);
  });

  it('nenhuma escrita em identity.session e possivel por vlos_app', async () => {
    const err = await expectRejection(() =>
      app.query(`UPDATE identity.session SET reauthenticated_at = now()`),
    );
    expect(err.message).toMatch(/permission denied|permissão negada/i);
  });
});
