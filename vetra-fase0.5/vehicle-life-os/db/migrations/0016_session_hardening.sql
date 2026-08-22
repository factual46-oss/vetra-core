-- =============================================================================
-- 0016_session_hardening  (Fase 1B — Bloco 3.5)
--
-- Retira de vlos_app toda capacidade de MUTACAO em identity.session.
--
-- MOTIVO
-- A janela de reautenticacao (Bloco 3) vive na coluna reauthenticated_at. A
-- policy session_self_update restringia a LINHA -- a propria sessao -- mas nao
-- a COLUNA. Com UPDATE de tabela, uma SQL injection em QUALQUER modulo que use
-- vlos_app -- hoje, ou na Fase 2 com veiculos, eventos e documentos -- poderia
-- abrir a janela da propria sessao e, com um token roubado, desativar o segundo
-- fator. Token roubado + injection em qualquer canto do produto era uma cadeia
-- completa.
--
-- POR QUE ISTO E POSSIVEL SEM PERDER FUNCIONALIDADE
-- Levantamento do codigo: markReauthenticated era a UNICA escrita em
-- identity.session feita por vlos_app. touch, revoke e revokeAllForUser ja
-- usavam vlos_auth. A leitura (isActiveForUser, listOwn, hasRecentReauth)
-- continua com vlos_app e continua sob RLS.
--
-- DEFESA EM PROFUNDIDADE, TRES CAMADAS
--   1. aplicacao : ReauthService so grava apos verificar a senha com Argon2id
--   2. privilegio: apenas vlos_auth pode escrever em identity.session
--   3. SQL       : WHERE id = $1 AND user_id = $2 AND sessao viva
--
-- Nenhuma das tres depende das outras para valer.
-- =============================================================================

SET search_path = public, extensions;

-- -----------------------------------------------------------------------------
-- 1. Revogacao
-- -----------------------------------------------------------------------------
REVOKE UPDATE ON identity.session FROM vlos_app;

-- A policy fica sem funcao: sem privilegio de UPDATE, ela nunca e avaliada.
-- Removida para que ninguem leia o schema no futuro e conclua que vlos_app
-- escreve em sessoes.
DROP POLICY IF EXISTS session_self_update ON identity.session;

COMMENT ON COLUMN identity.session.reauthenticated_at IS
  'Ultima prova de senha nesta sessao. Escrita EXCLUSIVAMENTE por vlos_auth, apos verificacao de senha no ReauthService. vlos_app nao tem UPDATE nesta tabela.';

-- -----------------------------------------------------------------------------
-- 2. Lista branca: a guarda permanente precisa refletir o novo estado
--
-- Sem esta remocao, ops.missing_privileges() passaria a apontar um privilegio
-- declarado e inexistente -- e o deploy falharia. E o mecanismo funcionando: a
-- declaracao e a realidade nao podem divergir em nenhuma das duas direcoes.
-- -----------------------------------------------------------------------------
DELETE FROM ops.privilege_allowlist
 WHERE grantee = 'vlos_app'
   AND object_type = 'TABLE'
   AND object_name = 'identity.session'
   AND privilege = 'UPDATE';

-- -----------------------------------------------------------------------------
-- 3. Verificacao bidirecional
-- -----------------------------------------------------------------------------
DO $do$
DECLARE
  v_extra text;
  v_falta text;
  v_pode  boolean;
BEGIN
  -- vlos_app perdeu mesmo a escrita?
  SELECT has_table_privilege('vlos_app', 'identity.session', 'UPDATE') INTO v_pode;
  IF v_pode THEN
    RAISE EXCEPTION 'vlos_app ainda possui UPDATE em identity.session';
  END IF;

  -- e mantem a leitura, de que o AuthGuard e o RecentAuthGuard dependem?
  SELECT has_table_privilege('vlos_app', 'identity.session', 'SELECT') INTO v_pode;
  IF NOT v_pode THEN
    RAISE EXCEPTION 'vlos_app perdeu SELECT em identity.session: a verificacao de sessao por requisicao pararia';
  END IF;

  -- vlos_auth continua podendo escrever?
  SELECT has_table_privilege('vlos_auth', 'identity.session', 'UPDATE') INTO v_pode;
  IF NOT v_pode THEN
    RAISE EXCEPTION 'vlos_auth perdeu UPDATE em identity.session';
  END IF;

  SELECT string_agg(format('%s -> %s %s : %s', grantee, object_type, object_name, privilege), E'\n  ')
    INTO v_extra FROM ops.unexpected_privileges();
  IF v_extra IS NOT NULL THEN
    RAISE EXCEPTION E'Privilegios existentes e nao declarados:\n  %', v_extra;
  END IF;

  SELECT string_agg(format('%s -> %s %s : %s', grantee, object_type, object_name, privilege), E'\n  ')
    INTO v_falta FROM ops.missing_privileges();
  IF v_falta IS NOT NULL THEN
    RAISE EXCEPTION E'Privilegios declarados e inexistentes:\n  %', v_falta;
  END IF;

  IF (SELECT count(*) FROM ops.tables_missing_rls()) > 0 THEN
    RAISE EXCEPTION 'tabelas sem RLS e sem isencao';
  END IF;

  RAISE NOTICE 'Bloco 3.5: vlos_app sem mutacao em identity.session; guarda consistente';
END
$do$;
