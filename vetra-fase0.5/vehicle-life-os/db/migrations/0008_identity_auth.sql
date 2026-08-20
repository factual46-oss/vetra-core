-- ============================================================================
-- 0008_identity_auth
-- Estruturas para autenticacao, credenciais, sessoes e tokens
-- ============================================================================

-- Tabela de credenciais (invisivel para vlos_app)
CREATE TABLE identity.credential (
  user_id       uuid PRIMARY KEY REFERENCES identity."user"(id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  algorithm     text NOT NULL DEFAULT 'argon2id',
  params        jsonb NOT NULL DEFAULT '{"m": 19456, "t": 3, "p": 1}'::jsonb,
  updated_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE identity.credential ENABLE ROW LEVEL SECURITY;
-- Sem policies para vlos_app: acesso exclusivo via SECURITY DEFINER

-- Tabela de sessoes
CREATE TABLE identity.session (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL REFERENCES identity."user"(id) ON DELETE CASCADE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  revoked_at    timestamptz,
  ip_address    inet,
  user_agent    text
);

CREATE INDEX session_user_ix ON identity.session (user_id);
CREATE INDEX session_active_ix ON identity.session (id) WHERE revoked_at IS NULL;

ALTER TABLE identity.session ENABLE ROW LEVEL SECURITY;

CREATE POLICY session_owner_policy ON identity.session
  FOR SELECT TO vlos_app
  USING (user_id = ops.current_user_id());

CREATE POLICY session_owner_update_policy ON identity.session
  FOR UPDATE TO vlos_app
  USING (user_id = ops.current_user_id());

CREATE POLICY session_auth_policy ON identity.session
  FOR ALL TO vlos_auth
  USING (true);

-- Tabela de refresh tokens (com hash e rotacao de familia)
CREATE TABLE identity.refresh_token (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id    uuid NOT NULL REFERENCES identity.session(id) ON DELETE CASCADE,
  family_id     uuid NOT NULL,
  token_hash    bytea NOT NULL UNIQUE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  used_at       timestamptz,
  revoked_at    timestamptz
);

CREATE INDEX refresh_token_hash_ix ON identity.refresh_token (token_hash);
CREATE INDEX refresh_token_family_ix ON identity.refresh_token (family_id);

ALTER TABLE identity.refresh_token ENABLE ROW LEVEL SECURITY;

CREATE POLICY refresh_token_auth_policy ON identity.refresh_token
  FOR ALL TO vlos_auth
  USING (true);

-- MFA TOTP e Recovery Codes
CREATE TABLE identity.mfa_totp (
  user_id         uuid PRIMARY KEY REFERENCES identity."user"(id) ON DELETE CASCADE,
  secret_enc      text NOT NULL,
  last_used_step  bigint NOT NULL DEFAULT 0,
  confirmed_at    timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE identity.mfa_totp ENABLE ROW LEVEL SECURITY;

CREATE POLICY mfa_totp_owner_policy ON identity.mfa_totp
  FOR SELECT TO vlos_app
  USING (user_id = ops.current_user_id());

CREATE POLICY mfa_totp_auth_policy ON identity.mfa_totp
  FOR ALL TO vlos_auth
  USING (true);

CREATE TABLE identity.recovery_code (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL REFERENCES identity."user"(id) ON DELETE CASCADE,
  code_hash     bytea NOT NULL,
  used_at       timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE identity.recovery_code ENABLE ROW LEVEL SECURITY;

CREATE POLICY recovery_code_owner_policy ON identity.recovery_code
  FOR SELECT TO vlos_app
  USING (user_id = ops.current_user_id());

CREATE POLICY recovery_code_auth_policy ON identity.recovery_code
  FOR ALL TO vlos_auth
  USING (true);

-- Single use tokens (reset / verificacao)
CREATE TABLE identity.single_use_token (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind          text NOT NULL,
  user_id       uuid NOT NULL REFERENCES identity."user"(id) ON DELETE CASCADE,
  token_hash    bytea NOT NULL UNIQUE,
  expires_at    timestamptz NOT NULL,
  used_at       timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE identity.single_use_token ENABLE ROW LEVEL SECURITY;

CREATE POLICY single_use_token_auth_policy ON identity.single_use_token
  FOR ALL TO vlos_auth
  USING (true);

-- Revogacao explicita dos defaults permissivos da 0005
REVOKE ALL ON identity.credential FROM vlos_app;
REVOKE ALL ON identity.refresh_token FROM vlos_app;
REVOKE ALL ON identity.single_use_token FROM vlos_app;
