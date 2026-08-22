-- =============================================================================
-- 0013_identity_recovery_mfa  (Fase 1B — Bloco 1)
--
-- Tabelas de recuperacao de conta, verificacao de e-mail e MFA, mais a coluna
-- de janela de reautenticacao.
--
-- ARMADILHA RECORRENTE DA 0005
-- ALTER DEFAULT PRIVILEGES concede SELECT/INSERT/UPDATE a vlos_app em TODA
-- tabela nova criada por vlos_migrator no schema identity. Sem os REVOKE
-- explicitos abaixo, o segredo do TOTP, os codigos de recuperacao e os tokens
-- de reset nasceriam legiveis pela role generica da aplicacao -- em silencio,
-- no dia zero. E a mesma armadilha que a 0008 teve de desarmar.
-- =============================================================================

SET search_path = public, extensions;

DO $do$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vlos_auth') THEN
    RAISE EXCEPTION
      'A role vlos_auth nao existe. Crie-a no bootstrap antes de migrar.';
  END IF;
END
$do$;

-- -----------------------------------------------------------------------------
-- Janela de reautenticacao (sudo mode)
--
-- Aditiva, anulavel, sem default: nenhuma consulta existente muda de resultado.
-- Nenhuma suite da Fase 1A faz SELECT * em identity.session, e as policies
-- permanecem exatamente como estao.
--
-- Motivo: uma sessao roubada nao pode cadastrar nem remover o segundo fator.
-- mfa/setup e mfa/activate exigem janela aberta; mfa/disable NAO usa a janela,
-- porque exige senha + TOTP na propria requisicao -- prova mais forte.
-- -----------------------------------------------------------------------------
ALTER TABLE identity.session ADD COLUMN reauthenticated_at timestamptz;

COMMENT ON COLUMN identity.session.reauthenticated_at IS
  'Ultima prova de senha nesta sessao. Operacoes criticas de MFA exigem janela recente. NULL = nunca reautenticou.';

-- -----------------------------------------------------------------------------
-- identity.single_use_token  -- reset de senha e verificacao de e-mail
--
-- Sem policy e sem grant para role alguma: alcancavel APENAS pelas duas funcoes
-- SECURITY DEFINER da 0014. Mesma decisao de identity.credential.
-- -----------------------------------------------------------------------------
CREATE TYPE identity.single_use_kind AS ENUM ('PASSWORD_RESET', 'EMAIL_VERIFICATION');

CREATE TABLE identity.single_use_token (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            uuid NOT NULL REFERENCES identity."user"(id) ON DELETE CASCADE,
  kind               identity.single_use_kind NOT NULL,
  token_hash         bytea NOT NULL UNIQUE,
  created_at         timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL,
  used_at            timestamptz,
  invalidated_at     timestamptz,
  invalidated_reason text,
  requested_ip_hash  bytea
);

-- Suporta a invalidacao em lote feita por issue_single_use_token.
CREATE INDEX single_use_token_live_ix ON identity.single_use_token (user_id, kind)
  WHERE used_at IS NULL AND invalidated_at IS NULL;

ALTER TABLE identity.single_use_token ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON identity.single_use_token FROM vlos_app;   -- desfaz o default da 0005

COMMENT ON TABLE identity.single_use_token IS
  'Tokens de uso unico. Sem policy e sem grant: so as funcoes SECURITY DEFINER de identity acessam.';
COMMENT ON COLUMN identity.single_use_token.token_hash IS
  'SHA-256 do token. O valor bruto nunca e persistido -- ha teste que varre todas as colunas.';

-- -----------------------------------------------------------------------------
-- identity.mfa_totp
--
-- user_id e CHAVE PRIMARIA: existe no maximo uma configuracao por usuario.
-- Multiplas configuracoes pendentes simultaneas sao impossiveis por construcao,
-- e nao por disciplina de codigo.
--
-- O segredo entra cifrado (AES-256-GCM, AAD ligada ao user_id, kek_version por
-- linha). vlos_app nao recebe privilegio algum: nem o ciphertext sai por ela.
-- -----------------------------------------------------------------------------
CREATE TABLE identity.mfa_totp (
  user_id        uuid PRIMARY KEY REFERENCES identity."user"(id) ON DELETE CASCADE,
  secret_cipher  bytea NOT NULL,
  secret_nonce   bytea NOT NULL,
  kek_version    smallint NOT NULL,
  confirmed_at   timestamptz,
  last_used_step bigint,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT mfa_totp_nonce_length CHECK (octet_length(secret_nonce) = 12),
  CONSTRAINT mfa_totp_kek_version_positive CHECK (kek_version > 0)
);

ALTER TABLE identity.mfa_totp ENABLE ROW LEVEL SECURITY;
CREATE POLICY mfa_totp_auth_all ON identity.mfa_totp
  FOR ALL TO vlos_auth USING (true) WITH CHECK (true);

REVOKE ALL ON identity.mfa_totp FROM vlos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity.mfa_totp TO vlos_auth;

CREATE TRIGGER mfa_totp_touch BEFORE UPDATE ON identity.mfa_totp
  FOR EACH ROW EXECUTE FUNCTION ops.touch_updated_at();

COMMENT ON COLUMN identity.mfa_totp.kek_version IS
  'Versao da APP_KEK usada na cifra. Permite rotacionar a chave sem invalidar o segundo fator de ninguem.';
COMMENT ON COLUMN identity.mfa_totp.last_used_step IS
  'Ultimo passo TOTP consumido. Anti-replay por UPDATE condicional; nunca SELECT-verifica-UPDATE.';

-- -----------------------------------------------------------------------------
-- identity.recovery_code
--
-- Apenas hash. batch_id permite regenerar invalidando o lote inteiro sem
-- apagar historico de uso.
-- -----------------------------------------------------------------------------
CREATE TABLE identity.recovery_code (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES identity."user"(id) ON DELETE CASCADE,
  batch_id     uuid NOT NULL,
  code_hash    bytea NOT NULL UNIQUE,
  generated_at timestamptz NOT NULL DEFAULT now(),
  used_at      timestamptz
);

CREATE INDEX recovery_code_available_ix ON identity.recovery_code (user_id)
  WHERE used_at IS NULL;

ALTER TABLE identity.recovery_code ENABLE ROW LEVEL SECURITY;
CREATE POLICY recovery_code_auth_all ON identity.recovery_code
  FOR ALL TO vlos_auth USING (true) WITH CHECK (true);

REVOKE ALL ON identity.recovery_code FROM vlos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity.recovery_code TO vlos_auth;

-- -----------------------------------------------------------------------------
-- identity.mfa_challenge  -- senha ja verificada, segundo fator pendente
--
-- No banco, e nao no Redis: a politica homologada da 1A e que o Redis falha
-- fechado em autenticacao. Um challenge perdido em restart do Redis viraria
-- falha de login inexplicavel no meio de um fluxo de dois passos, com a senha
-- ja verificada. O banco e a autoridade; o Redis e limitador.
-- -----------------------------------------------------------------------------
CREATE TABLE identity.mfa_challenge (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES identity."user"(id) ON DELETE CASCADE,
  token_hash  bytea NOT NULL UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz,
  ip_hash     bytea
);

CREATE INDEX mfa_challenge_live_ix ON identity.mfa_challenge (user_id)
  WHERE consumed_at IS NULL;

ALTER TABLE identity.mfa_challenge ENABLE ROW LEVEL SECURITY;
CREATE POLICY mfa_challenge_auth_all ON identity.mfa_challenge
  FOR ALL TO vlos_auth USING (true) WITH CHECK (true);

REVOKE ALL ON identity.mfa_challenge FROM vlos_app;
GRANT SELECT, INSERT, UPDATE ON identity.mfa_challenge TO vlos_auth;

-- -----------------------------------------------------------------------------
-- Verificacao imediata: as quatro tabelas novas precisam estar sob RLS.
-- -----------------------------------------------------------------------------
DO $do$
DECLARE v_n int;
BEGIN
  SELECT count(*) INTO v_n FROM ops.tables_missing_rls();
  IF v_n > 0 THEN
    RAISE EXCEPTION 'tabela sem RLS apos a 0013: %', v_n;
  END IF;
END
$do$;
