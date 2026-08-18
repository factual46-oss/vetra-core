-- =============================================================================
-- 0005_grants
-- Permissoes da role de aplicacao. Roda ao final de cada lote de migrations.
-- vlos_app nunca e dona das tabelas -> RLS se aplica a ela (Doc 02, secao 12).
--
-- AUD-01: USAGE em `extensions` e obrigatorio -- sem isso a aplicacao nao
--         resolve digest(), gen_random_bytes() nem o tipo citext.
-- AUD-09: admin_permission fica FORA do grant de escrita. Elevacao de
--         privilegio nao pode ser um UPDATE que a propria API consegue emitir.
-- =============================================================================

GRANT USAGE ON SCHEMA extensions TO vlos_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA extensions TO vlos_app;

GRANT USAGE ON SCHEMA identity, vehicle, knowledge, ops, ai TO vlos_app;

GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA identity, vehicle, knowledge, ops, ai TO vlos_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA identity, vehicle, knowledge, ops, ai TO vlos_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ops TO vlos_app;

-- Escrita em identity.admin_permission e revogada: quem concede privilegio
-- administrativo e a funcao identity.grant_admin_permission() (migration 0006),
-- que exige motivo e grava no log auditavel.
REVOKE INSERT, UPDATE ON identity.admin_permission FROM vlos_app;

-- DELETE nao e concedido em lugar nenhum: exclusao e sempre soft delete
-- (briefing secao 97). Expurgo legal roda com role dedicada, fora da API.
-- Nenhum DDL: vlos_app nao tem CREATE em nenhum schema nem no banco.

ALTER DEFAULT PRIVILEGES FOR ROLE vlos_migrator IN SCHEMA identity, vehicle, knowledge, ops, ai
  GRANT SELECT, INSERT, UPDATE ON TABLES TO vlos_app;
ALTER DEFAULT PRIVILEGES FOR ROLE vlos_migrator IN SCHEMA identity, vehicle, knowledge, ops, ai
  GRANT USAGE, SELECT ON SEQUENCES TO vlos_app;
