-- =============================================================================
-- 0011_audit_function_fixes
--
-- Tres defeitos encontrados na primeira execucao real das suites da Fase 1A.
-- Nenhum deles aparecia sem PostgreSQL de verdade -- e os tres estavam na
-- infraestrutura de auditoria, que e justamente a que precisa ser confiavel.
-- =============================================================================

SET search_path = public, extensions;

-- -----------------------------------------------------------------------------
-- FIX-1 -- `found` e variavel reservada do plpgsql
--
-- audit.verify_chain declarava um parametro OUT chamado `found`. FOUND e uma
-- variavel especial do plpgsql, do tipo BOOLEAN, existente em toda funcao.
-- A atribuicao `found := r.entry_hash` tentava colocar um bytea nela, gerando
-- "invalid input syntax for type boolean" com o hash no meio da mensagem.
--
-- Consequencia real: a verificacao de integridade da cadeia de auditoria NUNCA
-- funcionou -- ela sempre estourava antes de comparar qualquer coisa. O selo
-- por trigger estava correto; quem nunca funcionou foi a auditoria do selo.
--
-- Nome do parametro OUT nao muda com CREATE OR REPLACE: exige DROP.
-- -----------------------------------------------------------------------------
DROP FUNCTION IF EXISTS audit.verify_chain(bigint, int);

CREATE FUNCTION audit.verify_chain(p_from bigint DEFAULT 0, p_limit int DEFAULT 100000)
RETURNS TABLE (broken_at bigint, expected_hash bytea, stored_hash bytea) AS $fn$
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
      broken_at     := r.id;
      expected_hash := v_expected;
      stored_hash   := r.entry_hash;
      RETURN NEXT;
      RETURN;
    END IF;

    v_prev := r.entry_hash;
  END LOOP;
END;
$fn$ LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public, extensions;

-- -----------------------------------------------------------------------------
-- FIX-2 -- EXECUTE em funcao e concedido a PUBLIC por padrao
--
-- A 0007 revogou canonical_bytes de vlos_app, mas PUBLIC continuava com EXECUTE,
-- que e o padrao do PostgreSQL para toda funcao criada. vlos_app executava pela
-- porta dos fundos -- e o teste que deveria provar o contrario passava a
-- reprovar so agora, quando finalmente rodou contra banco real.
--
-- Revogar de uma role sem revogar de PUBLIC nao revoga nada.
-- -----------------------------------------------------------------------------
REVOKE ALL ON FUNCTION
  audit.canonical_bytes(timestamptz, text, uuid, text, text, uuid, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.verify_chain(bigint, int) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.seal_entry() FROM PUBLIC;

-- -----------------------------------------------------------------------------
-- FIX-3 -- RULE DO INSTEAD NOTHING apaga a checagem de privilegio
--
-- O rewriter do PostgreSQL descarta a query inteira ANTES da checagem de
-- permissao. Resultado: `UPDATE audit.log` por vlos_app -- que nao tem esse
-- privilegio -- nao levantava erro nenhum. Virava no-op silencioso.
--
-- A linha nao era alterada, entao a integridade estava preservada. Mas uma
-- tentativa de adulteracao respondia "ok" em vez de "negado", e isso e a
-- diferenca entre um ataque registrado e um ataque invisivel.
--
-- Trocamos as RULEs por trigger: agora a tentativa FALHA, alto e claro, para
-- qualquer um -- inclusive para a dona da tabela.
-- -----------------------------------------------------------------------------
DROP RULE IF EXISTS audit_log_no_update ON audit.log;
DROP RULE IF EXISTS audit_log_no_delete ON audit.log;

CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger AS $fn$
BEGIN
  RAISE EXCEPTION 'audit.log e append-only: % nao e permitido', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$fn$ LANGUAGE plpgsql SET search_path = pg_catalog, public, extensions;

REVOKE ALL ON FUNCTION audit.reject_mutation() FROM PUBLIC;

-- ERRCODE insufficient_privilege (42501) e o mesmo de "permission denied":
-- a mensagem do cliente fica indistinguivel de uma negacao de privilegio,
-- que e exatamente o que ela e.
CREATE TRIGGER audit_log_immutable
  BEFORE UPDATE OR DELETE ON audit.log
  FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();
