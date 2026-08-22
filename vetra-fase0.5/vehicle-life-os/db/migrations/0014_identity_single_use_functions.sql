-- =============================================================================
-- 0014_identity_single_use_functions  (Fase 1B — Bloco 1)
--
-- As duas funcoes SECURITY DEFINER que dao acesso a identity.single_use_token.
-- Com elas o projeto passa a ter SEIS funcoes SECURITY DEFINER:
--
--   identity.grant_admin_permission   (0006)
--   identity.register_user            (0009)
--   identity.authenticate_lookup      (0009)
--   identity.set_password             (0009)
--   identity.issue_single_use_token   (esta migration)
--   identity.consume_single_use_token (esta migration)
--
-- POR QUE DUAS E NAO UMA
-- A alternativa seria conceder INSERT/UPDATE de single_use_token a vlos_auth,
-- reduzindo uma funcao. Isso abriria a tabela inteira ao pool de autenticacao
-- em troca de economizar um caminho de vinte linhas. A revisao independente
-- decidiu pelas duas funcoes, e concordo: cada funcao aqui e um caminho
-- estreito, sem filtro livre e sem SQL vindo do chamador.
--
-- Nenhuma das duas devolve o token: elas recebem o hash e devolvem, no maximo,
-- um user_id. O valor bruto nunca transita pelo banco.
-- =============================================================================

SET search_path = public, extensions;

-- -----------------------------------------------------------------------------
-- issue_single_use_token
--
-- Emitir um token novo invalida os anteriores do mesmo kind, no MESMO comando.
-- Sem isso, um usuario que pede tres vezes "esqueci minha senha" fica com tres
-- tokens vivos, e o mais antigo -- possivelmente ja em maos erradas -- continua
-- valendo.
--
-- Invalidacao e insercao na mesma funcao para serem atomicas: nao existe
-- instante em que os antigos estejam mortos e o novo ainda nao exista.
-- -----------------------------------------------------------------------------
CREATE FUNCTION identity.issue_single_use_token(
  p_user_id     uuid,
  p_kind        identity.single_use_kind,
  p_token_hash  bytea,
  p_ttl_minutes int,
  p_ip_hash     bytea DEFAULT NULL
) RETURNS uuid AS $fn$
DECLARE
  v_id uuid;
BEGIN
  IF p_ttl_minutes IS NULL OR p_ttl_minutes <= 0 OR p_ttl_minutes > 1440 THEN
    RAISE EXCEPTION 'ttl invalido: %', p_ttl_minutes USING ERRCODE = 'check_violation';
  END IF;
  IF p_token_hash IS NULL OR octet_length(p_token_hash) <> 32 THEN
    RAISE EXCEPTION 'token_hash deve ser SHA-256 de 32 bytes' USING ERRCODE = 'check_violation';
  END IF;

  UPDATE identity.single_use_token
     SET invalidated_at = now(),
         invalidated_reason = 'SUPERSEDED'
   WHERE user_id = p_user_id
     AND kind = p_kind
     AND used_at IS NULL
     AND invalidated_at IS NULL;

  INSERT INTO identity.single_use_token
    (user_id, kind, token_hash, expires_at, requested_ip_hash)
  VALUES
    (p_user_id, p_kind, p_token_hash, now() + make_interval(mins => p_ttl_minutes), p_ip_hash)
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions;

-- -----------------------------------------------------------------------------
-- consume_single_use_token
--
-- Consumo ATOMICO, pelo mesmo padrao ja validado sob concorrencia real na
-- rotacao de refresh token da Fase 1A: um UPDATE condicional decide o vencedor.
-- Duas requisicoes simultaneas com o mesmo token disputam a mesma linha; o
-- PostgreSQL serializa, e a segunda nao encontra linha que satisfaca
-- `used_at IS NULL`. Sem lock explicito, sem transacao serializavel, sem janela.
--
-- NUNCA implementar como SELECT -> verifica -> UPDATE.
--
-- Retorna NULL para inexistente, expirado, ja usado ou invalidado: quem chama
-- nao consegue distinguir os casos, e portanto nao consegue transformar a
-- funcao em oraculo.
-- -----------------------------------------------------------------------------
CREATE FUNCTION identity.consume_single_use_token(
  p_kind       identity.single_use_kind,
  p_token_hash bytea
) RETURNS uuid AS $fn$
DECLARE
  v_user_id uuid;
BEGIN
  UPDATE identity.single_use_token
     SET used_at = now()
   WHERE token_hash = p_token_hash
     AND kind = p_kind
     AND used_at IS NULL
     AND invalidated_at IS NULL
     AND expires_at > now()
  RETURNING user_id INTO v_user_id;

  RETURN v_user_id;
END;
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions;

-- -----------------------------------------------------------------------------
-- Grants.
--
-- REVOKE ALL ... FROM PUBLIC antes de qualquer GRANT: toda funcao nasce com
-- EXECUTE para PUBLIC no PostgreSQL. Revogar de uma role sem revogar de PUBLIC
-- nao revoga nada -- foi exatamente o defeito corrigido na 0011.
-- -----------------------------------------------------------------------------
REVOKE ALL ON FUNCTION
  identity.issue_single_use_token(uuid, identity.single_use_kind, bytea, int, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION
  identity.consume_single_use_token(identity.single_use_kind, bytea) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
  identity.issue_single_use_token(uuid, identity.single_use_kind, bytea, int, bytea) TO vlos_auth;
GRANT EXECUTE ON FUNCTION
  identity.consume_single_use_token(identity.single_use_kind, bytea) TO vlos_auth;

COMMENT ON FUNCTION identity.issue_single_use_token(uuid, identity.single_use_kind, bytea, int, bytea) IS
  'Emite token de uso unico invalidando os anteriores do mesmo kind, atomicamente. Recebe apenas o hash.';
COMMENT ON FUNCTION identity.consume_single_use_token(identity.single_use_kind, bytea) IS
  'Consumo atomico por UPDATE condicional. Retorna NULL indistintamente para inexistente, expirado, usado ou invalidado.';
