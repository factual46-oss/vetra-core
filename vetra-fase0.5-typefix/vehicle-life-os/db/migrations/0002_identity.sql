-- =============================================================================
-- 0002_identity
-- Usuarios e organizacoes. Credenciais, sessoes e MFA entram na Fase 1.
-- =============================================================================

CREATE TABLE identity.organization (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  legal_name   text NOT NULL,
  trade_name   text,
  kind         text NOT NULL DEFAULT 'WORKSHOP',   -- WORKSHOP | DEALER | FLEET | INSURER
  is_verified  boolean NOT NULL DEFAULT false,
  verified_at  timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  deleted_at   timestamptz
);

CREATE TABLE identity."user" (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email              extensions.citext NOT NULL,   -- AUD-01: tipo qualificado
  email_verified_at  timestamptz,
  display_name       text NOT NULL,
  locale             text NOT NULL DEFAULT 'pt-BR',
  timezone           text NOT NULL DEFAULT 'America/Sao_Paulo',
  organization_id    uuid REFERENCES identity.organization(id),
  is_admin           boolean NOT NULL DEFAULT false,
  blocked_at         timestamptz,
  anonymized_at      timestamptz,       -- LGPD: exclusao = anonimizacao (Doc 03, secao 9)
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  deleted_at         timestamptz
);

-- e-mail unico apenas entre contas vivas: permite reuso apos anonimizacao
CREATE UNIQUE INDEX user_email_uk ON identity."user" (email) WHERE deleted_at IS NULL;

-- AUD-09: a role da aplicacao NAO escreve em admin_permission (ver 0006).
-- Concessao de privilegio administrativo passa por funcao SECURITY DEFINER
-- que audita a acao -- privilegio nao se concede por UPDATE solto.

CREATE TRIGGER user_touch BEFORE UPDATE ON identity."user"
  FOR EACH ROW EXECUTE FUNCTION ops.touch_updated_at();
CREATE TRIGGER organization_touch BEFORE UPDATE ON identity.organization
  FOR EACH ROW EXECUTE FUNCTION ops.touch_updated_at();

-- Permissoes administrativas granulares (Doc 03, secao 3):
-- admin NAO tem acesso irrestrito; cada capacidade e concedida uma a uma.
CREATE TABLE identity.admin_permission (
  user_id     uuid NOT NULL REFERENCES identity."user"(id) ON DELETE CASCADE,
  permission  text NOT NULL,   -- admin:metrics | admin:users | admin:vehicle_read | ...
  granted_by  uuid REFERENCES identity."user"(id),
  granted_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz,
  PRIMARY KEY (user_id, permission)
);
