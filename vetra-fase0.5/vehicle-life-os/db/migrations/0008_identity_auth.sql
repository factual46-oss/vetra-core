-- =============================================================================
-- 0008_identity_auth  (Fase 1A)
--
-- Tabelas de credencial, sessao e refresh token.
--
-- ATENCAO -- ARMADILHA DE PRIVILEGIO
-- A migration 0005 executa ALTER DEFAULT PRIVILEGES concedendo
-- SELECT/INSERT/UPDATE a vlos_app em TODA tabela nova criada por vlos_migrator
-- no schema identity. Sem os REVOKE explicitos abaixo, identity.credential
-- nasceria legivel pela role da aplicacao e a Alternativa B (secao 4 do plano)
-- estaria furada no dia zero, em silencio.
-- =============================================================================

SET search_path = public, extensions;

-- A role vlos_auth e criada no bootstrap (db/init/01-roles.sh e passo do CI),
-- nao aqui: criar role com LOGIN PASSWORD dentro de migration colocaria um
-- segredo em arquivo versionado, o que o item 23 do escopo proibe.
DO $do$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vlos_auth') THEN
    RAISE EXCEPTION
      'A role vlos_auth nao existe. Crie-a no bootstrap antes de migrar: CREATE ROLE vlos_auth LOGIN PASSWORD ... NOBYPASSRLS; GRANT CONNECT ON DATABASE ... TO vlos_auth;';
  END IF;
END
$do$;

GRANT USAGE ON SCHEMA identity, ops, audit, extensions TO vlos_auth;

-- -----------------------------------------------------------------------------
-- identity.credential
--
-- Alcancavel APENAS pelas funcoes SECURITY DEFINER da 0009. Nenhuma policy,
-- nenhum grant -- nem para vlos_app, nem para vlos_auth. A dona (vlos_migrator)
-- enxerga porque usamos ENABLE e nao FORCE, e e isso que permite as funcoes
-- definer operarem por um caminho de poucas linhas, sem filtro do chamador.
-- -----------------------------------------------------------------------------
CREATE TABLE identity.credential (
  user_id             uuid PRIMARY KEY REFERENCES identity."user"(id) ON DELETE CASCADE,
  password_hash       text NOT NULL,
  algorithm           text NOT NULL DEFAULT 'argon2id',
  params              jsonb NOT NULL,
  password_changed_at timestamptz NOT NULL DEFAULT now(),
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT credential_algorithm_supported CHECK (algorithm = 'argon2id')
);

ALTER TABLE identity.credential ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON identity.credential FROM vlos_app;   -- desfaz ALTER DEFAULT PRIVILEGES da 0005

COMMENT ON TABLE identity.credential IS
  'Hash de senha. Sem policy e sem grant: alcancavel so pelas funcoes SECURITY DEFINER de identity.';

-- -----------------------------------------------------------------------------
-- identity.session
--
-- Privacidade (item 35): guardamos HMAC de IP e user agent, nunca os valores em
-- claro. Servem para o usuario reconhecer sessoes suspeitas e para correlacionar
-- abuso -- nao para perfilamento.
-- -----------------------------------------------------------------------------
CREATE TABLE identity.session (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         uuid NOT NULL REFERENCES identity."user"(id) ON DELETE CASCADE,
  amr             text[] NOT NULL DEFAULT ARRAY['pwd'],
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_used_at    timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  revoked_at      timestamptz,
  revoked_reason  text,
  ip_hash         bytea,
  user_agent_hash bytea
);

CREATE INDEX session_user_active_ix ON identity.session (user_id, created_at DESC)
  WHERE revoked_at IS NULL;

ALTER TABLE identity.session ENABLE ROW LEVEL SECURITY;

-- A aplicacao le e revoga apenas as proprias sessoes. Esta policy tambem e o
-- que amarra sid a sub: a verificacao por requisicao roda sob app.user_id, entao
-- um sid de outro usuario simplesmente nao retorna linha.
CREATE POLICY session_self_select ON identity.session
  FOR SELECT TO vlos_app USING (user_id = ops.current_user_id());
CREATE POLICY session_self_update ON identity.session
  FOR UPDATE TO vlos_app USING (user_id = ops.current_user_id())
  WITH CHECK (user_id = ops.current_user_id());

-- O modulo de autenticacao cria sessao antes de existir contexto de usuario.
CREATE POLICY session_auth_all ON identity.session
  FOR ALL TO vlos_auth USING (true) WITH CHECK (true);

REVOKE ALL ON identity.session FROM vlos_app;
GRANT SELECT, UPDATE ON identity.session TO vlos_app;
GRANT SELECT, INSERT, UPDATE ON identity.session TO vlos_auth;

-- -----------------------------------------------------------------------------
-- identity.refresh_token
--
-- Guardamos SHA-256 do token, nunca o valor bruto. O isolamento aqui nao vem de
-- RLS por usuario -- no momento do refresh ainda nao existe identidade provada,
-- o proprio token E a credencial -- e sim da impossibilidade de adivinhar 256
-- bits. vlos_app nao recebe grant nenhum: refresh e assunto do modulo de auth.
-- -----------------------------------------------------------------------------
CREATE TABLE identity.refresh_token (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id     uuid NOT NULL REFERENCES identity.session(id) ON DELETE CASCADE,
  family_id      uuid NOT NULL,
  user_id        uuid NOT NULL REFERENCES identity."user"(id) ON DELETE CASCADE,
  token_hash     bytea NOT NULL UNIQUE,
  prev_id        uuid REFERENCES identity.refresh_token(id),
  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  used_at        timestamptz,
  revoked_at     timestamptz,
  revoked_reason text
);

CREATE INDEX refresh_token_family_ix  ON identity.refresh_token (family_id) WHERE revoked_at IS NULL;
CREATE INDEX refresh_token_session_ix ON identity.refresh_token (session_id);

ALTER TABLE identity.refresh_token ENABLE ROW LEVEL SECURITY;
CREATE POLICY refresh_token_auth_all ON identity.refresh_token
  FOR ALL TO vlos_auth USING (true) WITH CHECK (true);

REVOKE ALL ON identity.refresh_token FROM vlos_app;
GRANT SELECT, INSERT, UPDATE ON identity.refresh_token TO vlos_auth;

COMMENT ON COLUMN identity.refresh_token.token_hash IS
  'SHA-256 do token. O valor bruto nunca e persistido -- ha teste que varre todas as colunas para provar isso.';

-- -----------------------------------------------------------------------------
-- Auditoria: o modulo de autenticacao escreve eventos sem contexto de usuario.
-- Mesma politica append-only da 0007 -- INSERT e so.
-- -----------------------------------------------------------------------------
GRANT INSERT ON audit.log TO vlos_auth;
GRANT USAGE, SELECT ON SEQUENCE audit.log_id_seq TO vlos_auth;
CREATE POLICY audit_log_append_only_auth ON audit.log
  FOR INSERT TO vlos_auth WITH CHECK (true);

CREATE TRIGGER credential_touch BEFORE UPDATE ON identity.credential
  FOR EACH ROW EXECUTE FUNCTION ops.touch_updated_at();
