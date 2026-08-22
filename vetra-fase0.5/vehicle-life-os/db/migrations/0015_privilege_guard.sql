-- =============================================================================
-- 0015_privilege_guard  (Fase 1B — Bloco 1)
--
-- Converte a lista branca da 0010 em guarda PERMANENTE, e amplia o escopo.
--
-- PROBLEMA 1 -- a guarda da 0010 expirou sem avisar
-- Ela vivia dentro de um bloco DO: executou uma vez, no momento da migration, e
-- nunca mais. A partir do primeiro GRANT seguinte virou documentacao. Aqui ela
-- passa a ser FUNCAO, chamada pelo CI e por teste a cada execucao -- o mesmo
-- padrao que ja funciona em ops.tables_missing_rls().
--
-- PROBLEMA 2 -- a guarda so enxergava tabelas
-- information_schema.table_privileges nao cobre EXECUTE em funcao, USAGE em
-- schema nem privilegio de sequence. O estado real do projeto tem 7 grants de
-- EXECUTE, 4 de USAGE em schema e 4 em sequences. A Fase 1B cria mais dois
-- EXECUTE. A guarda anterior seria cega justamente para a categoria nova.
--
-- PROBLEMA 3 -- aclexplode(NULL) devolve zero linhas
-- Objeto que nunca recebeu GRANT nem REVOKE tem acl NULL, e o padrao do
-- PostgreSQL para FUNCOES inclui EXECUTE para PUBLIC. Uma guarda ingenua
-- enxergaria zero privilegios exatamente nas funcoes mais perigosas: as que
-- ninguem tocou. Foi literalmente o defeito da 0011 (canonical_bytes acessivel
-- via PUBLIC apesar do REVOKE nominal). Por isso todo acl passa por
-- coalesce(acl, acldefault(...)) antes de ser explodido.
--
-- PROBLEMA 4 -- lista branca que so olha para um lado
-- A verificacao e BIDIRECIONAL: falha se existir privilegio nao declarado E se
-- existir privilegio declarado que nao existe. O segundo caso pega erro de
-- digitacao na lista e revogacao feita sem atualizar a declaracao.
-- =============================================================================

SET search_path = public, extensions;

-- -----------------------------------------------------------------------------
-- Higiene: as funcoes de ops nunca tiveram REVOKE FROM PUBLIC e portanto estao
-- executaveis por qualquer um. Risco baixo (leem catalogo e configuracao de
-- sessao), mas e privilegio que ninguem concedeu conscientemente.
--
-- ATENCAO as duas dependencias, motivo dos GRANT nominais logo abaixo:
--   · ops.current_user_id()  e chamada DENTRO das policies de RLS
--   · ops.touch_updated_at() e trigger disparado por vlos_auth em mfa_totp
-- Revogar de PUBLIC sem conceder nominalmente quebraria as duas.
-- -----------------------------------------------------------------------------
REVOKE ALL ON FUNCTION ops.touch_updated_at()   FROM PUBLIC;
REVOKE ALL ON FUNCTION ops.current_user_id()    FROM PUBLIC;
REVOKE ALL ON FUNCTION ops.tables_missing_rls() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION ops.current_user_id()  TO vlos_app, vlos_auth;
GRANT EXECUTE ON FUNCTION ops.touch_updated_at() TO vlos_app, vlos_auth;

-- -----------------------------------------------------------------------------
-- Lista branca declarada
-- -----------------------------------------------------------------------------
CREATE TABLE ops.privilege_allowlist (
  grantee     text NOT NULL,
  object_type text NOT NULL,   -- TABLE | SEQUENCE | FUNCTION | SCHEMA
  object_name text NOT NULL,   -- qualificado; funcoes com assinatura canonica
  privilege   text NOT NULL,
  reason      text NOT NULL,
  declared_in text NOT NULL,
  PRIMARY KEY (grantee, object_type, object_name, privilege)
);

REVOKE ALL ON ops.privilege_allowlist FROM vlos_app, vlos_auth;

INSERT INTO ops.rls_exemption (schema_name, table_name, reason, decided_by) VALUES
  ('ops', 'privilege_allowlist',
   'Governanca de privilegios, sem dado de usuario. Escrita apenas por migration.', 'fase-1b');

COMMENT ON TABLE ops.privilege_allowlist IS
  'Declaracao de intencao revisada por humano. NAO e fotografia do estado: derivar automaticamente carimbaria tambem os erros existentes.';

-- -----------------------------------------------------------------------------
-- ops.privilege_snapshot() -- estado REAL, uniforme para as quatro classes
--
-- Serve tambem de ferramenta: rodar `SELECT * FROM ops.privilege_snapshot();`
-- produz a base para revisar e declarar a lista branca linha a linha.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ops.privilege_snapshot()
RETURNS TABLE (grantee text, object_type text, object_name text, privilege text) AS $fn$
  WITH relations AS (
    SELECT CASE WHEN c.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END AS object_type,
           format('%s.%s', n.nspname, c.relname) AS object_name,
           -- relkind usa 'S' maiusculo para sequence; acldefault usa 's'
           -- minusculo. O CASE abaixo e deliberado.
           (aclexplode(coalesce(c.relacl,
              acldefault(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END, c.relowner)))).*
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S')
      AND n.nspname IN ('identity', 'vehicle', 'knowledge', 'ops', 'ai', 'audit')
  ),
  routines AS (
    SELECT 'FUNCTION' AS object_type,
           format('%s.%s(%s)', n.nspname, p.proname,
                  pg_get_function_identity_arguments(p.oid)) AS object_name,
           (aclexplode(coalesce(p.proacl, acldefault('f', p.proowner)))).*
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    -- `extensions` fica FORA de proposito: pgcrypto, citext e btree_gist trazem
    -- dezenas de funcoes com EXECUTE para PUBLIC por design do proprio pacote.
    -- Inclui-las encheria a lista branca de ruido de terceiros e escondendo o
    -- que importa, que sao os objetos do projeto.
    WHERE n.nspname IN ('identity', 'vehicle', 'knowledge', 'ops', 'ai', 'audit')
  ),
  schemas AS (
    SELECT 'SCHEMA' AS object_type,
           n.nspname AS object_name,
           (aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner)))).*
    FROM pg_namespace n
    WHERE n.nspname IN ('identity', 'vehicle', 'knowledge', 'ops', 'ai',
                        'audit', 'extensions', 'public')
  ),
  todos AS (
    SELECT * FROM relations
    UNION ALL SELECT * FROM routines
    UNION ALL SELECT * FROM schemas
  )
  SELECT g.role_name, t.object_type, t.object_name, t.privilege_type::text
  FROM todos t
  CROSS JOIN LATERAL (
    SELECT CASE WHEN t.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(t.grantee) END AS role_name
  ) g
  -- PUBLIC entra na vigilancia: e por onde privilegio aparece sem ninguem
  -- ter concedido nada.
  WHERE g.role_name IN ('vlos_app', 'vlos_auth', 'PUBLIC')
  ORDER BY 1, 2, 3, 4;
$fn$ LANGUAGE sql STABLE SET search_path = pg_catalog, public, extensions;

-- Privilegio que EXISTE e nao foi declarado.
CREATE OR REPLACE FUNCTION ops.unexpected_privileges()
RETURNS TABLE (grantee text, object_type text, object_name text, privilege text) AS $fn$
  SELECT s.grantee, s.object_type, s.object_name, s.privilege
  FROM ops.privilege_snapshot() s
  WHERE NOT EXISTS (
    SELECT 1 FROM ops.privilege_allowlist a
    WHERE a.grantee = s.grantee
      AND a.object_type = s.object_type
      AND a.object_name = s.object_name
      AND a.privilege = s.privilege
  )
  ORDER BY 1, 2, 3, 4;
$fn$ LANGUAGE sql STABLE SET search_path = pg_catalog, public, extensions;

-- Privilegio DECLARADO que nao existe. Pega erro de digitacao na lista e
-- revogacao feita sem atualizar a declaracao.
CREATE OR REPLACE FUNCTION ops.missing_privileges()
RETURNS TABLE (grantee text, object_type text, object_name text, privilege text) AS $fn$
  SELECT a.grantee, a.object_type, a.object_name, a.privilege
  FROM ops.privilege_allowlist a
  WHERE NOT EXISTS (
    SELECT 1 FROM ops.privilege_snapshot() s
    WHERE s.grantee = a.grantee
      AND s.object_type = a.object_type
      AND s.object_name = a.object_name
      AND s.privilege = a.privilege
  )
  ORDER BY 1, 2, 3, 4;
$fn$ LANGUAGE sql STABLE SET search_path = pg_catalog, public, extensions;

REVOKE ALL ON FUNCTION ops.privilege_snapshot()    FROM PUBLIC;
REVOKE ALL ON FUNCTION ops.unexpected_privileges() FROM PUBLIC;
REVOKE ALL ON FUNCTION ops.missing_privileges()    FROM PUBLIC;

-- -----------------------------------------------------------------------------
-- Declaracao do estado esperado apos 0001..0015.
--
-- Derivada da leitura das migrations, linha a linha, com motivo e origem.
-- A calibracao final vem do primeiro CI (Opcao B autorizada): se houver
-- divergencia, ops.unexpected_privileges() e ops.missing_privileges() imprimem
-- exatamente o que sobra e o que falta.
-- -----------------------------------------------------------------------------
INSERT INTO ops.privilege_allowlist (grantee, object_type, object_name, privilege, reason, declared_in) VALUES
  -- ---- SCHEMA -------------------------------------------------------------
  ('vlos_app',  'SCHEMA', 'identity',   'USAGE', 'acesso ao dominio de identidade',        '0005'),
  ('vlos_app',  'SCHEMA', 'vehicle',    'USAGE', 'catalogo de tipos de evento',            '0005'),
  ('vlos_app',  'SCHEMA', 'knowledge',  'USAGE', 'base de conhecimento (Fase 2)',          '0005'),
  ('vlos_app',  'SCHEMA', 'ops',        'USAGE', 'funcoes utilitarias e governanca',       '0005'),
  ('vlos_app',  'SCHEMA', 'ai',         'USAGE', 'consumo de IA (Fase 7)',                 '0005'),
  ('vlos_app',  'SCHEMA', 'extensions', 'USAGE', 'digest, citext e afins',                 '0005'),
  ('vlos_app',  'SCHEMA', 'audit',      'USAGE', 'escrita append-only no log auditavel',   '0004'),
  ('vlos_auth', 'SCHEMA', 'identity',   'USAGE', 'fluxo de autenticacao',                  '0008'),
  ('vlos_auth', 'SCHEMA', 'ops',        'USAGE', 'ops.current_user_id e trigger de touch', '0008'),
  ('vlos_auth', 'SCHEMA', 'audit',      'USAGE', 'auditoria de autenticacao',              '0008'),
  ('vlos_auth', 'SCHEMA', 'extensions', 'USAGE', 'digest e afins',                         '0008'),

  -- ---- TABLE / vlos_app ---------------------------------------------------
  ('vlos_app',  'TABLE', 'identity.user',             'SELECT', 'perfil proprio sob RLS',                       '0005'),
  ('vlos_app',  'TABLE', 'identity.user',             'UPDATE', 'perfil proprio sob RLS',                       '0005'),
  ('vlos_app',  'TABLE', 'identity.organization',     'SELECT', 'membros sob RLS',                              '0005'),
  ('vlos_app',  'TABLE', 'identity.organization',     'INSERT', 'bloqueado por RLS; grant mantido por contrato de teste da 0.5', '0005'),
  ('vlos_app',  'TABLE', 'identity.organization',     'UPDATE', 'bloqueado por RLS',                            '0005'),
  ('vlos_app',  'TABLE', 'identity.admin_permission', 'SELECT', 'leitura das proprias permissoes',              '0005'),
  ('vlos_app',  'TABLE', 'identity.session',          'SELECT', 'verificacao de sessao por requisicao',          '0008'),
  ('vlos_app',  'TABLE', 'identity.session',          'UPDATE', 'revogacao pelo proprio usuario',               '0008'),
  ('vlos_app',  'TABLE', 'vehicle.event_type',        'SELECT', 'catalogo de referencia',                       '0005'),
  ('vlos_app',  'TABLE', 'vehicle.event_type',        'INSERT', 'catalogo de referencia',                       '0005'),
  ('vlos_app',  'TABLE', 'vehicle.event_type',        'UPDATE', 'catalogo de referencia',                       '0005'),
  ('vlos_app',  'TABLE', 'ops.rls_exemption',         'SELECT', 'governanca de RLS',                            '0005'),
  ('vlos_app',  'TABLE', 'ops.rls_exemption',         'INSERT', 'governanca de RLS',                            '0005'),
  ('vlos_app',  'TABLE', 'ops.rls_exemption',         'UPDATE', 'governanca de RLS',                            '0005'),
  ('vlos_app',  'TABLE', 'audit.log',                 'INSERT', 'append-only; SELECT revogado na 0007',          '0004'),
  ('vlos_app',  'TABLE', 'audit.chain_anchor',        'INSERT', 'ancoragem externa; SELECT revogado na 0007',    '0006'),

  -- ---- TABLE / vlos_auth --------------------------------------------------
  ('vlos_auth', 'TABLE', 'identity.session',       'SELECT', 'fluxo de autenticacao',                '0008'),
  ('vlos_auth', 'TABLE', 'identity.session',       'INSERT', 'criacao de sessao no login',           '0008'),
  ('vlos_auth', 'TABLE', 'identity.session',       'UPDATE', 'revogacao e janela de reautenticacao', '0008'),
  ('vlos_auth', 'TABLE', 'identity.refresh_token', 'SELECT', 'rotacao e deteccao de replay',         '0008'),
  ('vlos_auth', 'TABLE', 'identity.refresh_token', 'INSERT', 'emissao do proximo token',             '0008'),
  ('vlos_auth', 'TABLE', 'identity.refresh_token', 'UPDATE', 'consumo atomico e revogacao',          '0008'),
  ('vlos_auth', 'TABLE', 'identity.mfa_totp',      'SELECT', 'verificacao de TOTP',                  '0013'),
  ('vlos_auth', 'TABLE', 'identity.mfa_totp',      'INSERT', 'enrolamento',                          '0013'),
  ('vlos_auth', 'TABLE', 'identity.mfa_totp',      'UPDATE', 'confirmacao e anti-replay',            '0013'),
  ('vlos_auth', 'TABLE', 'identity.mfa_totp',      'DELETE', 'desativacao do segundo fator',         '0013'),
  ('vlos_auth', 'TABLE', 'identity.recovery_code', 'SELECT', 'verificacao de codigo',                '0013'),
  ('vlos_auth', 'TABLE', 'identity.recovery_code', 'INSERT', 'geracao do lote',                      '0013'),
  ('vlos_auth', 'TABLE', 'identity.recovery_code', 'UPDATE', 'consumo de uso unico',                 '0013'),
  ('vlos_auth', 'TABLE', 'identity.recovery_code', 'DELETE', 'regeneracao do lote',                  '0013'),
  ('vlos_auth', 'TABLE', 'identity.mfa_challenge', 'SELECT', 'login em dois passos',                 '0013'),
  ('vlos_auth', 'TABLE', 'identity.mfa_challenge', 'INSERT', 'login em dois passos',                 '0013'),
  ('vlos_auth', 'TABLE', 'identity.mfa_challenge', 'UPDATE', 'consumo do desafio',                   '0013'),
  ('vlos_auth', 'TABLE', 'audit.log',              'INSERT', 'auditoria de autenticacao',            '0008'),

  -- ---- SEQUENCE -----------------------------------------------------------
  ('vlos_app',  'SEQUENCE', 'audit.log_id_seq',          'USAGE',  'insercao no log auditavel',  '0004'),
  ('vlos_app',  'SEQUENCE', 'audit.log_id_seq',          'SELECT', 'insercao no log auditavel',  '0004'),
  ('vlos_app',  'SEQUENCE', 'audit.chain_anchor_id_seq', 'USAGE',  'insercao de ancora',         '0006'),
  ('vlos_app',  'SEQUENCE', 'audit.chain_anchor_id_seq', 'SELECT', 'insercao de ancora',         '0006'),
  ('vlos_auth', 'SEQUENCE', 'audit.log_id_seq',          'USAGE',  'auditoria de autenticacao',  '0008'),
  ('vlos_auth', 'SEQUENCE', 'audit.log_id_seq',          'SELECT', 'auditoria de autenticacao',  '0008'),

  -- ---- FUNCTION -----------------------------------------------------------
  ('vlos_app',  'FUNCTION', 'ops.current_user_id()',  'EXECUTE', 'chamada dentro das policies de RLS', '0005'),
  ('vlos_app',  'FUNCTION', 'ops.touch_updated_at()', 'EXECUTE', 'trigger de updated_at',              '0005'),
  ('vlos_auth', 'FUNCTION', 'ops.current_user_id()',  'EXECUTE', 'coerencia com o pool de auth',       '0015'),
  ('vlos_auth', 'FUNCTION', 'ops.touch_updated_at()', 'EXECUTE', 'trigger de touch em mfa_totp',       '0015'),
  ('vlos_app',  'FUNCTION', 'identity.grant_admin_permission(uuid, text, text, timestamp with time zone)',
                            'EXECUTE', 'unica porta para conceder privilegio administrativo', '0006'),
  ('vlos_auth', 'FUNCTION', 'identity.register_user(text, text, text, jsonb)',
                            'EXECUTE', 'cadastro: nao ha policy de INSERT em identity.user', '0009'),
  ('vlos_auth', 'FUNCTION', 'identity.authenticate_lookup(text)',
                            'EXECUTE', 'login antes de existir contexto de usuario', '0009'),
  ('vlos_auth', 'FUNCTION', 'identity.set_password(uuid, text, jsonb, boolean)',
                            'EXECUTE', 'credential e inacessivel a qualquer role de aplicacao', '0009'),
  ('vlos_auth', 'FUNCTION', 'identity.issue_single_use_token(uuid, identity.single_use_kind, bytea, integer, bytea)',
                            'EXECUTE', 'emissao atomica com invalidacao dos anteriores', '0014'),
  ('vlos_auth', 'FUNCTION', 'identity.consume_single_use_token(identity.single_use_kind, bytea)',
                            'EXECUTE', 'consumo atomico de uso unico', '0014');

-- -----------------------------------------------------------------------------
-- Verificacao final. Falha o deploy nos dois sentidos.
-- -----------------------------------------------------------------------------
DO $do$
DECLARE
  v_extra text;
  v_falta text;
  v_rls   int;
BEGIN
  SELECT string_agg(format('%s -> %s %s : %s', grantee, object_type, object_name, privilege), E'\n  ')
    INTO v_extra FROM ops.unexpected_privileges();

  SELECT string_agg(format('%s -> %s %s : %s', grantee, object_type, object_name, privilege), E'\n  ')
    INTO v_falta FROM ops.missing_privileges();

  SELECT count(*) INTO v_rls FROM ops.tables_missing_rls();

  IF v_extra IS NOT NULL THEN
    RAISE EXCEPTION E'Privilegios EXISTENTES e nao declarados:\n  %\nSe forem intencionais, declare-os em 0015 no mesmo commit.', v_extra;
  END IF;

  IF v_falta IS NOT NULL THEN
    RAISE EXCEPTION E'Privilegios DECLARADOS e inexistentes:\n  %\nCorrija a declaracao ou conceda o privilegio.', v_falta;
  END IF;

  IF v_rls > 0 THEN
    RAISE EXCEPTION 'tabelas sem RLS e sem isencao: %', v_rls;
  END IF;

  RAISE NOTICE 'Fase 1B: guarda permanente de privilegios ativa e consistente';
END
$do$;
