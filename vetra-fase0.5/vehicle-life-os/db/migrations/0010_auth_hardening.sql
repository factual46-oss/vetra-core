-- ============================================================================
-- 0010_auth_hardening
-- Trava de seguranca por lista branca e validacao de RLS
-- ============================================================================

DO $$
DECLARE
  v_missing int;
  v_illegal_grants int;
BEGIN
  -- 1. Garante que nenhuma tabela ficou sem RLS
  SELECT count(*) INTO v_missing FROM ops.tables_missing_rls();
  IF v_missing > 0 THEN
    RAISE EXCEPTION 'Hardening falhou: existem % tabelas sem RLS ativo!', v_missing;
  END IF;

  -- 2. Lista branca: vlos_app JAMAIS pode ter permissao direta em identity.credential
  SELECT count(*) INTO v_illegal_grants
  FROM information_schema.role_table_grants
  WHERE grantee = 'vlos_app'
    AND table_schema = 'identity'
    AND table_name = 'credential';

  IF v_illegal_grants > 0 THEN
    RAISE EXCEPTION 'Hardening falhou: vlos_app possui privilegios diretos indevidos em identity.credential!';
  END IF;
END $$;
