-- ============================================================================
-- 0009_identity_functions
-- Funcoes SECURITY DEFINER restritas exclusivamente a role vlos_auth
-- ============================================================================

-- 1. Cadastro de usuario
CREATE OR REPLACE FUNCTION identity.register_user(
  p_email     text,
  p_name      text,
  p_hash      text,
  p_params    jsonb DEFAULT '{"m": 19456, "t": 3, "p": 1}'::jsonb
) RETURNS uuid AS $fn$
DECLARE
  v_user_id uuid;
BEGIN
  INSERT INTO identity."user" (email, name)
  VALUES (p_email, p_name)
  RETURNING id INTO v_user_id;

  INSERT INTO identity.credential (user_id, password_hash, params)
  VALUES (v_user_id, p_hash, p_params);

  RETURN v_user_id;
END;
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, identity;

-- 2. Lookup de credencial por e-mail normalizado
CREATE OR REPLACE FUNCTION identity.authenticate_lookup(
  p_email_norm text
) RETURNS TABLE (
  user_id       uuid,
  password_hash text,
  params        jsonb,
  is_active     boolean
) AS $fn$
BEGIN
  RETURN QUERY
  SELECT u.id, c.password_hash, c.params, (u.deleted_at IS NULL)
  FROM identity."user" u
  JOIN identity.credential c ON c.user_id = u.id
  WHERE u.email = p_email_norm AND u.deleted_at IS NULL;
END;
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, identity;

-- 3. Atualizacao de senha
CREATE OR REPLACE FUNCTION identity.set_password(
  p_user_id uuid,
  p_hash    text,
  p_params  jsonb DEFAULT '{"m": 19456, "t": 3, "p": 1}'::jsonb
) RETURNS void AS $fn$
BEGIN
  UPDATE identity.credential
  SET password_hash = p_hash,
      params = p_params,
      updated_at = now()
  WHERE user_id = p_user_id;
END;
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, identity;

-- 4. Consumo atomico de token de uso unico
CREATE OR REPLACE FUNCTION identity.consume_single_use_token(
  p_kind       text,
  p_token_hash bytea
) RETURNS uuid AS $fn$
DECLARE
  v_user_id uuid;
BEGIN
  UPDATE identity.single_use_token
  SET used_at = now()
  WHERE kind = p_kind
    AND token_hash = p_token_hash
    AND used_at IS NULL
    AND expires_at > now()
  RETURNING user_id INTO v_user_id;

  RETURN v_user_id;
END;
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, identity;

-- Restricao de execucao apenas para vlos_auth
REVOKE ALL ON FUNCTION identity.register_user(text, text, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.authenticate_lookup(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.set_password(uuid, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.consume_single_use_token(text, bytea) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION identity.register_user(text, text, text, jsonb) TO vlos_auth;
GRANT EXECUTE ON FUNCTION identity.authenticate_lookup(text) TO vlos_auth;
GRANT EXECUTE ON FUNCTION identity.set_password(uuid, text, jsonb) TO vlos_auth;
GRANT EXECUTE ON FUNCTION identity.consume_single_use_token(text, bytea) TO vlos_auth;
