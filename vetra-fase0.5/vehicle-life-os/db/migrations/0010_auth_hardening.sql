-- =============================================================================
-- 0010_auth_hardening  (Fase 1A)
--
-- Esta migration nao cria nada. Ela VERIFICA por LISTA BRANCA e falha o deploy
-- se qualquer role de aplicacao tiver um privilegio que nao esteja declarado
-- abaixo.
--
-- Lista branca, e nao lista negra, por causa da armadilha da 0005: o
-- ALTER DEFAULT PRIVILEGES concede SELECT/INSERT/UPDATE a vlos_app em TODA
-- tabela nova do schema identity. Uma lista negra so pega o que alguem lembrou
-- de listar; a lista branca pega tudo que apareceu sem autorizacao -- inclusive
-- tabelas que ainda nao existem.
--
-- Consequencia aceita: conceder um privilegio novo, legitimo, exige atualizar
-- esta lista no mesmo commit. E o ponto.
-- =============================================================================

SET search_path = public, extensions;

-- Menor privilegio: a aplicacao nunca insere em identity."user" -- o cadastro
-- passa por identity.register_user(). A RLS ja bloqueava (nao ha policy de
-- INSERT); agora o privilegio tambem sai.
--
-- identity.organization MANTEM o INSERT de proposito: o teste de isolamento da
-- Fase 0.5 documenta que a escrita e barrada pela RLS, e revogar o privilegio
-- mudaria a mensagem de erro, alterando um contrato ja homologado. Nos dois
-- casos a escrita e impossivel; a diferenca e apenas qual camada recusa.
REVOKE INSERT ON identity."user" FROM vlos_app;

DO $do$
DECLARE
  v_unexpected text;
  v_count int;
BEGIN
  -- 1. LISTA BRANCA de privilegios de tabela das roles de aplicacao
  WITH allowed (grantee, schema_name, table_name, privilege) AS (
    VALUES
      -- vlos_app
      ('vlos_app',  'identity', 'user',             'SELECT'),
      ('vlos_app',  'identity', 'user',             'UPDATE'),
      ('vlos_app',  'identity', 'organization',     'SELECT'),
      ('vlos_app',  'identity', 'organization',     'INSERT'),
      ('vlos_app',  'identity', 'organization',     'UPDATE'),
      ('vlos_app',  'identity', 'admin_permission', 'SELECT'),
      ('vlos_app',  'identity', 'session',          'SELECT'),
      ('vlos_app',  'identity', 'session',          'UPDATE'),
      ('vlos_app',  'vehicle',  'event_type',       'SELECT'),
      ('vlos_app',  'vehicle',  'event_type',       'INSERT'),
      ('vlos_app',  'vehicle',  'event_type',       'UPDATE'),
      ('vlos_app',  'ops',      'rls_exemption',    'SELECT'),
      ('vlos_app',  'ops',      'rls_exemption',    'INSERT'),
      ('vlos_app',  'ops',      'rls_exemption',    'UPDATE'),
      ('vlos_app',  'audit',    'log',              'INSERT'),
      ('vlos_app',  'audit',    'chain_anchor',     'INSERT'),
      -- vlos_auth: sessao, refresh token e escrita de auditoria. Nada mais.
      ('vlos_auth', 'identity', 'session',          'SELECT'),
      ('vlos_auth', 'identity', 'session',          'INSERT'),
      ('vlos_auth', 'identity', 'session',          'UPDATE'),
      ('vlos_auth', 'identity', 'refresh_token',    'SELECT'),
      ('vlos_auth', 'identity', 'refresh_token',    'INSERT'),
      ('vlos_auth', 'identity', 'refresh_token',    'UPDATE'),
      ('vlos_auth', 'audit',    'log',              'INSERT')
  )
  SELECT string_agg(format('%s -> %s.%s:%s', p.grantee, p.table_schema, p.table_name, p.privilege_type), E'\n  ')
    INTO v_unexpected
  FROM information_schema.table_privileges p
  WHERE p.grantee IN ('vlos_app', 'vlos_auth')
    AND NOT EXISTS (
      SELECT 1 FROM allowed a
      WHERE a.grantee = p.grantee
        AND a.schema_name = p.table_schema
        AND a.table_name = p.table_name
        AND a.privilege = p.privilege_type
    );

  IF v_unexpected IS NOT NULL THEN
    RAISE EXCEPTION E'Privilegio fora da lista branca:\n  %\nSe for intencional, declare-o em 0010_auth_hardening.sql no mesmo commit.', v_unexpected;
  END IF;

  -- 2. As funcoes de credencial sao executaveis apenas por vlos_auth
  SELECT count(*) INTO v_count
  FROM information_schema.routine_privileges
  WHERE grantee = 'vlos_app'
    AND routine_schema = 'identity'
    AND routine_name IN ('register_user', 'authenticate_lookup', 'set_password');

  IF v_count > 0 THEN
    RAISE EXCEPTION 'vlos_app pode executar % funcao(oes) de credencial. A Alternativa B depende disso nao acontecer.', v_count;
  END IF;

  -- 3. Nenhuma role de aplicacao com BYPASSRLS ou posse de tabela
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('vlos_app', 'vlos_auth') AND rolbypassrls) THEN
    RAISE EXCEPTION 'role de aplicacao com BYPASSRLS';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
    WHERE r.rolname IN ('vlos_auth', 'vlos_app') AND c.relkind = 'r'
  ) THEN
    RAISE EXCEPTION 'role de aplicacao e dona de tabela';
  END IF;

  -- 4. Guarda de RLS da Fase 0.5 continua limpa (agora com as tabelas novas)
  SELECT count(*) INTO v_count FROM ops.tables_missing_rls();
  IF v_count > 0 THEN
    RAISE EXCEPTION 'existem % tabela(s) sem RLS e sem isencao', v_count;
  END IF;

  RAISE NOTICE 'Fase 1A: lista branca de privilegios verificada';
END
$do$;
