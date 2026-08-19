DO $$ BEGIN
  CREATE ROLE vlos_app WITH LOGIN PASSWORD 'vetra_password';
EXCEPTION WHEN duplicate_object THEN
  ALTER ROLE vlos_app WITH LOGIN PASSWORD 'vetra_password';
END $$;
-- =============================================================================
-- 0004_audit
-- Log auditavel com encadeamento por hash (briefing secoes 34 e 51).
--
-- AUD-01: digest() e de pgcrypto, que agora vive no schema `extensions` e e
-- sempre chamada qualificada. Antes, com as extensoes em `public` e o REVOKE do
-- init script, este trigger falharia para vlos_app -- ou seja, NENHUMA acao
-- auditavel seria gravada em producao.
--
-- Decisao: o hash e calculado NO BANCO, por trigger. A aplicacao nunca
-- fornece prev_hash nem entry_hash. Isso garante que existe UMA unica
-- implementacao da canonicalizacao -- a mesma usada pela verificacao --
-- e que nenhum caminho de codigo consegue gravar uma entrada nao selada.
-- =============================================================================

CREATE TABLE audit.log (
  id             bigserial PRIMARY KEY,
  occurred_at    timestamptz NOT NULL DEFAULT now(),
  actor_type     text NOT NULL,          -- USER | ADMIN | SYSTEM | WORKSHOP | ANONYMOUS
  actor_user_id  uuid,
  action         text NOT NULL,          -- VEHICLE_VIEW | DOCUMENT_DOWNLOAD | ADMIN_ACCESS_VEHICLE | ...
  object_type    text,
  object_id      uuid,
  reason         text,                   -- obrigatorio para acao administrativa (validado na aplicacao)
  metadata       jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip_hash        bytea,                  -- HMAC, nunca IP em claro (briefing secao 87)
  request_id     text,
  prev_hash      bytea,
  entry_hash     bytea NOT NULL
);

CREATE INDEX audit_log_actor_ix  ON audit.log (actor_user_id, occurred_at DESC);
CREATE INDEX audit_log_object_ix ON audit.log (object_type, object_id, occurred_at DESC);
CREATE INDEX audit_log_action_ix ON audit.log (action, occurred_at DESC);

-- -----------------------------------------------------------------------------
-- Canonicalizacao: uma unica definicao, usada pelo selo e pela verificacao.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit.canonical_bytes(
  p_occurred_at   timestamptz,
  p_actor_type    text,
  p_actor_user_id uuid,
  p_action        text,
  p_object_type   text,
  p_object_id     uuid,
  p_reason        text,
  p_metadata      jsonb
) RETURNS bytea AS $fn$
  SELECT convert_to(
    to_char(p_occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || '|' ||
    p_actor_type                        || '|' ||
    coalesce(p_actor_user_id::text, '') || '|' ||
    p_action                            || '|' ||
    coalesce(p_object_type, '')         || '|' ||
    coalesce(p_object_id::text, '')     || '|' ||
    coalesce(p_reason, '')              || '|' ||
    jsonb_strip_nulls(p_metadata)::text,
    'UTF8'
  );
$fn$ LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public, extensions;

-- -----------------------------------------------------------------------------
-- Selo: encadeia cada entrada a anterior.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit.seal_entry() RETURNS trigger AS $fn$
DECLARE
  v_prev bytea;
BEGIN
  -- serializa os appends: a cadeia nao admite duas entradas com o mesmo antecessor
  PERFORM pg_advisory_xact_lock(918273646);

  SELECT entry_hash INTO v_prev FROM audit.log ORDER BY id DESC LIMIT 1;

  NEW.prev_hash  := v_prev;
  NEW.entry_hash := extensions.digest(
    coalesce(v_prev, ''::bytea) ||
    audit.canonical_bytes(NEW.occurred_at, NEW.actor_type, NEW.actor_user_id, NEW.action,
                          NEW.object_type, NEW.object_id, NEW.reason, NEW.metadata),
    'sha256'
  );
  RETURN NEW;
END;
$fn$ LANGUAGE plpgsql SET search_path = pg_catalog, public, extensions;

CREATE TRIGGER audit_log_seal BEFORE INSERT ON audit.log
  FOR EACH ROW EXECUTE FUNCTION audit.seal_entry();

-- Append-only estrito: a aplicacao NUNCA altera, apaga nem le diretamente o log
REVOKE ALL ON audit.log FROM vlos_app;
GRANT INSERT ON audit.log TO vlos_app;
GRANT USAGE, SELECT ON SEQUENCE audit.log_id_seq TO vlos_app;

-- A aplicacao nao calcula hashes diretamente
REVOKE ALL ON FUNCTION audit.canonical_bytes(timestamptz, text, uuid, text, text, uuid, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.canonical_bytes(timestamptz, text, uuid, text, text, uuid, text, jsonb) FROM vlos_app;

-- -----------------------------------------------------------------------------
-- Verificacao da cadeia (job diario -- Doc 04, secao 6).
-- Retorna zero linhas quando integra.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit.verify_chain(p_from bigint DEFAULT 0, p_limit int DEFAULT 100000)
RETURNS TABLE (broken_at bigint, expected bytea, found bytea) AS $fn$
DECLARE
  r          record;
  v_prev     bytea;
  v_expected bytea;
BEGIN
  SELECT entry_hash INTO v_prev FROM audit.log WHERE id < p_from ORDER BY id DESC LIMIT 1;

  FOR r IN SELECT * FROM audit.log WHERE id >= p_from ORDER BY id LIMIT p_limit LOOP
    v_expected := extensions.digest(
      coalesce(v_prev, ''::bytea) ||
      audit.canonical_bytes(r.occurred_at, r.actor_type, r.actor_user_id, r.action,
                            r.object_type, r.object_id, r.reason, r.metadata),
      'sha256'
    );

    IF r.prev_hash IS DISTINCT FROM v_prev OR r.entry_hash IS DISTINCT FROM v_expected THEN
      RETURN QUERY SELECT r.id, v_expected, r.entry_hash;
      RETURN;
    END IF;

    v_prev := r.entry_hash;
  END LOOP;
END;
$fn$ LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public, extensions;

-- A role da aplicacao insere e le; nunca altera nem apaga.
GRANT USAGE ON SCHEMA audit TO vlos_app;
GRANT INSERT, SELECT ON audit.log TO vlos_app;
GRANT USAGE, SELECT ON SEQUENCE audit.log_id_seq TO vlos_app;
GRANT EXECUTE ON FUNCTION audit.canonical_bytes(timestamptz, text, uuid, text, text, uuid, text, jsonb) TO vlos_app;
