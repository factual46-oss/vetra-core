-- =============================================================================
-- 0012_audit_chain_ordering
--
-- Defeito de concorrencia no selo da cadeia de auditoria, revelado quando o
-- verify_chain finalmente passou a executar (0011) e quando a Fase 1A passou a
-- gravar auditoria de varios arquivos de teste em paralelo.
--
-- O PROBLEMA
-- `id bigserial` e avaliado ao montar a tupla, ANTES do trigger BEFORE INSERT.
-- O advisory lock que serializa o encadeamento e adquirido DENTRO do trigger.
-- As duas ordens podem divergir:
--
--   tx1 recebe id=13 | tx2 recebe id=14
--   tx2 pega o lock primeiro, encadeia sobre o id 12, commita
--   tx1 pega o lock, le "ultimo = 14" e encadeia sobre 14
--
-- A cadeia fica correta em ordem de COMMIT e quebrada em ordem de ID -- que e
-- como verify_chain percorre. Sob carga concorrente real, a verificacao de
-- integridade acusaria adulteracao onde nao houve nenhuma: um alarme falso na
-- unica ferramenta que existe para detectar alarme verdadeiro.
--
-- A CORRECAO
-- Reatribuir o id DENTRO do trigger, ja sob o lock. A partir daqui a ordem de
-- id e, por construcao, a mesma ordem em que os hashes foram encadeados.
-- Os ids consumidos pelo DEFAULT viram lacunas na sequencia -- irrelevante,
-- porque a cadeia depende da ORDEM, nao da continuidade dos numeros.
-- =============================================================================

SET search_path = public, extensions;

CREATE OR REPLACE FUNCTION audit.seal_entry() RETURNS trigger AS $fn$
DECLARE
  v_prev bytea;
BEGIN
  -- serializa os appends: a cadeia nao admite duas entradas com o mesmo antecessor
  PERFORM pg_advisory_xact_lock(918273646);

  -- Reatribuicao sob o lock: garante que a ordem dos ids seja a mesma ordem do
  -- encadeamento. Sem isto, transacoes concorrentes produzem cadeia valida em
  -- ordem de commit e invalida em ordem de id.
  NEW.id := nextval('audit.log_id_seq');

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
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions;

REVOKE ALL ON FUNCTION audit.seal_entry() FROM PUBLIC;

COMMENT ON FUNCTION audit.seal_entry() IS
  'SECURITY DEFINER: le o hash anterior com privilegio da dona e reatribui o id sob o mesmo lock, para que ordem de id e ordem de encadeamento nunca divirjam.';
