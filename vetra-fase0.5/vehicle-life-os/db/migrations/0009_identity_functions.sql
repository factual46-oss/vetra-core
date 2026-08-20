-- =============================================================================
-- 0009_identity_functions  (Fase 1A)
--
-- As tres funcoes SECURITY DEFINER do nucleo de autenticacao. Cada funcao e
-- superficie de ataque, entao a lista e fechada e cada uma tem escopo estreito:
-- nenhuma aceita filtro livre, nenhuma lista usuarios, nenhuma recebe SQL.
--
-- owner        : vlos_migrator (quem roda a migration)
-- search_path  : fixo, objetos qualificados
-- grants       : REVOKE ALL FROM PUBLIC, EXECUTE apenas para vlos_auth
-- =============================================================================

SET search_path = public, extensions;

-- -----------------------------------------------------------------------------
-- register_user
-- Existe porque identity."user" nao tem policy de INSERT -- e nao deve ter.
-- Levanta unique_violation em e-mail duplicado; a API traduz para uma resposta
-- generica, para nao transformar o cadastro em oraculo de existencia.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION identity.register_user(
  p_email         text,
  p_display_name  text,
  p_password_hash text,
  p_params        jsonb
) RETURNS uuid AS $fn$
DECLARE
  v_user_id uuid;
BEGIN
  IF p_email IS NULL OR btrim(p_email) = '' THEN
    RAISE EXCEPTION 'e-mail obrigatorio' USING ERRCODE = 'check_violation';
  END IF;
  IF p_password_hash IS NULL OR length(p_password_hash) < 20 THEN
    RAISE EXCEPTION 'hash de senha invalido' USING ERRCODE = 'check_violation';
  END IF;

  INSERT INTO identity."user" (email, display_name)
  VALUES (p_email::extensions.citext, p_display_name)
  RETURNING id INTO v_user_id;

  INSERT INTO identity.credential (user_id, password_hash, algorithm, params)
  VALUES (v_user_id, p_password_hash, 'argon2id', p_params);

  RETURN v_user_id;
END;
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions;

-- -----------------------------------------------------------------------------
-- authenticate_lookup
-- Login precisa achar o usuario antes de existir contexto de usuario.
--
-- LIMITE CONHECIDO (secao 4 do plano, Alternativa B): esta funcao devolve o hash
-- a quem a executa. Ela nao torna o hash inextraivel -- reduz o ALCANCE (so o
-- modulo de auth, via vlos_auth, consegue chama-la) e o VALOR do que sai (sem o
-- AUTH_PEPPER, que vive apenas na memoria da aplicacao, o hash e inutil para
-- ataque offline). Nao afirme mais do que isso em documentacao.
--
-- Para e-mail inexistente retorna ZERO linhas; a aplicacao executa mesmo assim
-- uma verificacao Argon2 contra um hash fixo, para nao criar diferenca grosseira
-- de tempo entre "nao existe" e "senha errada".
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION identity.authenticate_lookup(p_email text)
RETURNS TABLE (
  user_id        uuid,
  password_hash  text,
  algorithm      text,
  params         jsonb,
  is_blocked     boolean,
  email_verified boolean
) AS $fn$
  SELECT u.id,
         c.password_hash,
         c.algorithm,
         c.params,
         (u.blocked_at IS NOT NULL),
         (u.email_verified_at IS NOT NULL)
  FROM identity."user" u
  JOIN identity.credential c ON c.user_id = u.id
  WHERE u.email = p_email::extensions.citext
    AND u.deleted_at IS NULL
    AND u.anonymized_at IS NULL;
$fn$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, extensions;

-- -----------------------------------------------------------------------------
-- set_password
-- identity.credential e inacessivel a qualquer role de aplicacao; trocar ou
-- re-hashear senha passa obrigatoriamente por aqui.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION identity.set_password(
  p_user_id       uuid,
  p_password_hash text,
  p_params        jsonb,
  p_rehash_only   boolean DEFAULT false
) RETURNS void AS $fn$
BEGIN
  IF p_password_hash IS NULL OR length(p_password_hash) < 20 THEN
    RAISE EXCEPTION 'hash de senha invalido' USING ERRCODE = 'check_violation';
  END IF;

  UPDATE identity.credential
     SET password_hash = p_password_hash,
         params        = p_params,
         algorithm     = 'argon2id',
         -- re-hash por endurecimento de parametros nao e troca de senha:
         -- password_changed_at so muda quando o usuario realmente trocou.
         password_changed_at = CASE WHEN p_rehash_only THEN password_changed_at ELSE now() END
   WHERE user_id = p_user_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'credencial inexistente' USING ERRCODE = 'no_data_found';
  END IF;
END;
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, extensions;

-- -----------------------------------------------------------------------------
-- Grants: PUBLIC nunca; apenas vlos_auth. vlos_app NAO recebe EXECUTE --
-- e ha teste provando que a chamada por vlos_app e negada.
-- -----------------------------------------------------------------------------
REVOKE ALL ON FUNCTION identity.register_user(text, text, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.authenticate_lookup(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.set_password(uuid, text, jsonb, boolean) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION identity.register_user(text, text, text, jsonb) TO vlos_auth;
GRANT EXECUTE ON FUNCTION identity.authenticate_lookup(text) TO vlos_auth;
GRANT EXECUTE ON FUNCTION identity.set_password(uuid, text, jsonb, boolean) TO vlos_auth;
