-- =============================================================================
-- 0006_rls_pattern
--
-- Gate da Fase 0, itens 7, 8, 9 e 12.
--
-- Esta migration nao adiciona funcionalidade. Ela transforma "vamos usar RLS na
-- Fase 1" em algo que o banco cobra sozinho:
--   1. estabelece o padrao de policy nas tabelas de usuario que ja existem;
--   2. cria um verificador que aponta qualquer tabela futura sem RLS;
--   3. torna a concessao de privilegio administrativo auditavel por construcao;
--   4. prepara a ancoragem externa do log auditavel.
--
-- DECISAO (AUD-05): usamos ENABLE ROW LEVEL SECURITY, e NAO FORCE.
--   FORCE sujeita tambem o DONO da tabela as policies. Como vlos_app nunca e
--   dona de nada, ENABLE ja isola a aplicacao -- e FORCE quebraria as funcoes
--   SECURITY DEFINER (login, cadastro) que precisam enxergar a tabela inteira
--   por um caminho estreito e auditado.
--   O risco residual e a aplicacao conectar como vlos_migrator. Isso e bloqueado
--   na validacao de ambiente da API (config/env.ts) e testado em tests/security.
-- =============================================================================

SET search_path = public, extensions;

-- -----------------------------------------------------------------------------
-- 1. Padrao de RLS nas tabelas de usuario existentes
-- -----------------------------------------------------------------------------

ALTER TABLE identity."user" ENABLE ROW LEVEL SECURITY;

-- Um usuario enxerga a si mesmo. Nada mais.
-- Sem app.user_id definido, ops.current_user_id() e NULL e a comparacao e falsa:
-- zero linhas. Falha fechado, que e o comportamento desejado.
CREATE POLICY user_self_select ON identity."user"
  FOR SELECT TO vlos_app
  USING (id = ops.current_user_id() AND deleted_at IS NULL);

CREATE POLICY user_self_update ON identity."user"
  FOR UPDATE TO vlos_app
  USING (id = ops.current_user_id() AND deleted_at IS NULL)
  WITH CHECK (id = ops.current_user_id());

-- Nao existe policy de INSERT: cadastro nao acontece por INSERT direto da API.
-- Requisito obrigatorio da Fase 1: identity.register_user() e
-- identity.authenticate_lookup() como SECURITY DEFINER, unicas portas para
-- criar conta e buscar por e-mail antes de existir contexto de usuario.

ALTER TABLE identity.admin_permission ENABLE ROW LEVEL SECURITY;

CREATE POLICY admin_permission_self_select ON identity.admin_permission
  FOR SELECT TO vlos_app
  USING (user_id = ops.current_user_id());

-- -----------------------------------------------------------------------------
-- 2. Verificador: nenhuma tabela de dado de usuario sem RLS
-- -----------------------------------------------------------------------------

CREATE TABLE ops.rls_exemption (
  schema_name text NOT NULL,
  table_name  text NOT NULL,
  reason      text NOT NULL,
  decided_by  text NOT NULL,
  decided_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (schema_name, table_name)
);

COMMENT ON TABLE ops.rls_exemption IS
  'Isencao explicita e justificada de RLS. Tabela de referencia (catalogo) pode ser isenta; tabela com dado de usuario, nunca.';

INSERT INTO ops.rls_exemption (schema_name, table_name, reason, decided_by) VALUES
  ('vehicle', 'event_type',    'Catalogo de tipos de evento: dado de referencia, identico para todos os usuarios.', 'fase-0'),
  ('ops',     'rls_exemption', 'Tabela de governanca, sem dado de usuario. Escrita apenas por migration.',          'fase-0'),
  ('identity',  'tentativa_ddl', 'Tabela de teste temporaria para validacao de DDL.',                                      'fase-0');
-- Retorna zero linhas quando o modelo esta integro. O CI falha se retornar algo.
CREATE OR REPLACE FUNCTION ops.tables_missing_rls()
RETURNS TABLE (schema_name text, table_name text) AS $fn$
  SELECT n.nspname::text, c.relname::text
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind = 'r'
    AND n.nspname IN ('identity', 'vehicle', 'ops', 'ai')
    AND NOT c.relrowsecurity
    AND NOT EXISTS (
      SELECT 1 FROM ops.rls_exemption e
      WHERE e.schema_name = n.nspname AND e.table_name = c.relname
    )
  ORDER BY 1, 2;
$fn$ LANGUAGE sql STABLE SET search_path = pg_catalog, public, extensions;

COMMENT ON FUNCTION ops.tables_missing_rls() IS
  'Guarda de regressao. Toda tabela nova em identity/vehicle/ops/ai precisa de RLS ou de isencao justificada.';

-- Schema `knowledge` fica fora da verificacao por definicao: e a base de
-- conhecimento do modelo (marcas, versoes, intervalos oficiais), publica por
-- natureza e sem vinculo com usuario (briefing secao 56).

-- -----------------------------------------------------------------------------
-- 3. Privilegio administrativo: concessao auditada por construcao (gate item 12)
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION identity.grant_admin_permission(
  p_target_user_id uuid,
  p_permission     text,
  p_reason         text,
  p_expires_at     timestamptz DEFAULT NULL
) RETURNS void AS $fn$
DECLARE
  v_granter uuid := ops.current_user_id();
BEGIN
  IF v_granter IS NULL THEN
    RAISE EXCEPTION 'contexto de usuario ausente: app.user_id nao definido';
  END IF;

  IF p_reason IS NULL OR length(btrim(p_reason)) < 10 THEN
    RAISE EXCEPTION 'motivo obrigatorio (minimo 10 caracteres) para conceder privilegio administrativo';
  END IF;

  -- quem concede precisa da permissao de conceder
  IF NOT EXISTS (
    SELECT 1 FROM identity.admin_permission
    WHERE user_id = v_granter
      AND permission = 'admin:grant'
      AND (expires_at IS NULL OR expires_at > now())
  ) THEN
    RAISE EXCEPTION 'usuario % nao possui admin:grant', v_granter;
  END IF;

  INSERT INTO identity.admin_permission (user_id, permission, granted_by, expires_at)
  VALUES (p_target_user_id, p_permission, v_granter, p_expires_at)
  ON CONFLICT (user_id, permission) DO UPDATE
    SET granted_by = EXCLUDED.granted_by,
        granted_at = now(),
        expires_at = EXCLUDED.expires_at;

  INSERT INTO audit.log (actor_type, actor_user_id, action, object_type, object_id, reason, metadata)
  VALUES ('ADMIN', v_granter, 'ADMIN_PERMISSION_GRANTED', 'user', p_target_user_id, p_reason,
          jsonb_build_object('permission', p_permission, 'expires_at', p_expires_at));
END;
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions;

REVOKE ALL ON FUNCTION identity.grant_admin_permission(uuid, text, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.grant_admin_permission(uuid, text, text, timestamptz) TO vlos_app;

COMMENT ON FUNCTION identity.grant_admin_permission(uuid, text, text, timestamptz) IS
  'Unica porta para conceder privilegio administrativo. Exige motivo e grava no log auditavel. A role da aplicacao nao tem INSERT/UPDATE direto na tabela.';

-- -----------------------------------------------------------------------------
-- 4. Ancoragem externa do log auditavel (gate item 11)
-- -----------------------------------------------------------------------------

CREATE TABLE audit.chain_anchor (
  id            bigserial PRIMARY KEY,
  anchored_at   timestamptz NOT NULL DEFAULT now(),
  last_entry_id bigint NOT NULL,
  last_hash     bytea NOT NULL,
  entry_count   bigint NOT NULL,
  destination   text NOT NULL,    -- 'S3_OBJECT_LOCK' | 'OFFSITE_APPEND_ONLY' | 'MANUAL_EXPORT'
  external_ref  text,             -- chave do objeto / id do recibo externo
  verified_at   timestamptz
);

COMMENT ON TABLE audit.chain_anchor IS
  'LIMITACAO CONHECIDA: hash chain prova consistencia interna, nao imutabilidade fisica. '
  'Quem controla o banco pode reescrever a cadeia inteira. A prova real vem de ancorar '
  'periodicamente (last_entry_id, last_hash) em storage externo append-only/WORM, fora do '
  'alcance do administrador do servidor. Esta tabela guarda essas ancoras; o job de export '
  'e requisito da Fase 9 (Doc 04, secao 6).';

GRANT SELECT, INSERT ON audit.chain_anchor TO vlos_app;
GRANT USAGE, SELECT ON SEQUENCE audit.chain_anchor_id_seq TO vlos_app;
ALTER TABLE audit.chain_anchor ENABLE ROW LEVEL SECURITY;
CREATE POLICY chain_anchor_no_access ON audit.chain_anchor FOR SELECT TO vlos_app USING (false);
