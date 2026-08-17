-- =============================================================================
-- 0007_audit_and_org_hardening
--
-- Fase 0.5 -- correcoes da auditoria externa independente.
--   AUD-22: identity.organization sem RLS (apontada pela propria guarda 0006).
--   AUD-23: vlos_app com SELECT global em audit.log.
--
-- POR QUE MIGRATION NOVA E NAO EDICAO DA ORIGINAL
-- A regra do projeto permite corrigir migration nunca aplicada, e nenhuma delas
-- foi aplicada ainda. Mesmo assim, aqui a correcao e MIGRATION NOVA, porque ela
-- e integralmente expressavel de forma aditiva (ENABLE RLS, CREATE POLICY,
-- REVOKE, CREATE OR REPLACE). O caso do AUD-01 era diferente: a extensao nascia
-- no schema errado, e uma corretiva teria que move-la -- deixando para sempre
-- uma migration que cria o problema e outra que o desfaz. Editar historia e
-- excecao para quando a alternativa e pior, nao conveniencia.
-- =============================================================================

SET search_path = public, extensions;

-- =============================================================================
-- AUD-22 -- identity.organization protegida por padrao
--
-- ANALISE ARQUITETURAL
-- A entidade representa oficina, concessionaria, frota e seguradora. Contem
-- razao social, nome fantasia, tipo e status de verificacao -- e, por meio de
-- identity."user".organization_id, revela QUEM trabalha em QUAL empresa.
--
-- Ha a tentacao de trata-la como dado publico ("nome de oficina e publico").
-- Isso confunde duas coisas: o diretorio publico de oficinas VERIFICADAS, que
-- e um produto futuro com curadoria, e a tabela operacional, onde tambem vivem
-- organizacoes nao verificadas, cadastros em analise e frotas privadas -- para
-- quem a simples existencia do registro e informacao de negocio.
--
-- Decisao: entidade protegida por padrao. Sem isencao. Visibilidade publica,
-- quando existir, sera opt-in explicito com policy propria (Fase 2), nunca o
-- default. Vazamento e irreversivel; restricao e sempre relaxavel depois.
-- =============================================================================

ALTER TABLE identity.organization ENABLE ROW LEVEL SECURITY;

-- Somente quem pertence a organizacao a enxerga.
-- A subconsulta le identity."user", que tambem tem RLS: executada como invoker,
-- ela so devolve a propria linha do usuario. Nao ha recursao -- a policy de
-- "user" nao referencia organization.
CREATE POLICY organization_member_select ON identity.organization
  FOR SELECT TO vlos_app
  USING (
    deleted_at IS NULL
    AND id = (SELECT u.organization_id FROM identity."user" u WHERE u.id = ops.current_user_id())
  );

-- Nenhuma policy de INSERT ou UPDATE: a aplicacao nao cria nem altera
-- organizacao. O onboarding de oficina (Fase 2) tera funcao SECURITY DEFINER
-- propria, com verificacao de CNPJ e registro na auditoria -- pelo mesmo motivo
-- que privilegio administrativo nao se concede por UPDATE solto.

COMMENT ON TABLE identity.organization IS
  'Protegida por RLS: visivel apenas a membros. Diretorio publico de oficinas verificadas sera opt-in com policy propria (Fase 2).';

-- =============================================================================
-- AUD-23 -- audit.log deixa de ser legivel pela role da aplicacao
--
-- RAZAO TECNICA DO SELECT ORIGINAL (e por que ela nao justifica mante-lo)
-- audit.seal_entry() le o entry_hash da ultima linha para encadear a nova. Como
-- a funcao era SECURITY INVOKER, ela rodava como vlos_app e exigia SELECT na
-- tabela -- e esse SELECT, sendo privilegio de tabela, valia para QUALQUER
-- consulta da API, nao so para o trigger.
--
-- Correcao: a funcao passa a SECURITY DEFINER. Ela le o hash anterior com o
-- privilegio da dona, dentro de um caminho de 4 linhas que nao aceita parametro
-- do chamador. A role da aplicacao perde a leitura e mantem apenas a escrita.
--
-- Resultado: vlos_app -> INSERT sim; SELECT, UPDATE, DELETE nao.
-- =============================================================================

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
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions;

REVOKE ALL ON FUNCTION audit.seal_entry() FROM PUBLIC;

COMMENT ON FUNCTION audit.seal_entry() IS
  'SECURITY DEFINER: le o hash anterior com privilegio da dona para que vlos_app nao precise de SELECT em audit.log. Nao aceita parametro do chamador.';

-- Privilegio de tabela: escrita apenas.
REVOKE SELECT ON audit.log FROM vlos_app;
REVOKE SELECT ON audit.chain_anchor FROM vlos_app;

-- A canonicalizacao nao e mais chamada pela aplicacao (so pelo trigger, que
-- roda como dona) nem deve ser: expor a funcao permitiria a um atacante com
-- execucao de SQL calcular hashes validos offline.
REVOKE EXECUTE ON FUNCTION
  audit.canonical_bytes(timestamptz, text, uuid, text, text, uuid, text, jsonb) FROM vlos_app;

-- Segunda camada: RLS. Se um GRANT de SELECT voltar por engano numa migration
-- futura, a ausencia de policy de leitura continua bloqueando.
ALTER TABLE audit.log ENABLE ROW LEVEL SECURITY;

-- RLS bloqueia INSERT quando nao ha policy com WITH CHECK. Esta e a unica
-- permissao da aplicacao sobre o log.
CREATE POLICY audit_log_append_only ON audit.log
  FOR INSERT TO vlos_app
  WITH CHECK (true);

-- Nao existe policy de SELECT. Consequencia pratica: `INSERT ... RETURNING`
-- em audit.log falha. E deliberado -- a aplicacao nao precisa do id da entrada.

COMMENT ON TABLE audit.log IS
  'Append-only para a aplicacao: INSERT permitido, SELECT/UPDATE/DELETE nao. '
  'Leitura administrativa e requisito da Fase 9, por caminho privilegiado proprio -- ver comentario abaixo.';

-- -----------------------------------------------------------------------------
-- CAMINHO DE LEITURA -- requisito registrado, nao implementado agora
--
-- Duas necessidades legitimas de ler o log, cada uma com seu caminho:
--
--   1. Titular (LGPD, direito de acesso): funcao SECURITY DEFINER
--      audit.list_own_entries(), filtrando por actor_user_id = ops.current_user_id()
--      e por objetos do proprio usuario. Escopo fechado, sem parametro de filtro
--      livre. Fase 1, junto com a area de conta.
--
--   2. Console administrativo: role separada `vlos_audit_reader`, com SELECT em
--      audit.log e pool de conexao proprio, usada apenas pelo painel admin --
--      que por sua vez exige permissao nominal e grava o proprio acesso.
--      Fase 9. Criar a role agora, sem consumidor, seria privilegio ocioso.
--
-- Nao implementados aqui porque nao ha consumidor: nem area de conta, nem painel.
-- -----------------------------------------------------------------------------
