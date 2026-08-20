#!/bin/bash
# Executado UMA VEZ, na primeira inicializacao do container postgres.
# Cria a separacao de roles exigida pelos Documentos 02 (secao 12) e 03 (secao 3):
#   vlos_migrator -> dona das tabelas e dos schemas, roda migrations. Nao usada pela API.
#   vlos_app      -> usada pela API e pelos workers. SEM BYPASSRLS, SEM DDL, SEM DELETE.
#
# AUD-03: existia referencia a uma terceira role, vlos_audit_w, que nunca foi
# criada nem concedida. Decisao da auditoria: NAO criar. O isolamento do log
# auditavel ja e obtido por (a) grants de vlos_app limitados a INSERT+SELECT em
# audit.log e (b) RULEs que anulam UPDATE/DELETE inclusive para a dona da tabela.
# Uma terceira role exigiria um segundo pool de conexao sem ganho de seguranca --
# e documentacao que descreve um controle inexistente e pior que nenhuma.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
  CREATE ROLE vlos_migrator LOGIN PASSWORD '${MIGRATOR_DB_PASSWORD}' NOBYPASSRLS;
  CREATE ROLE vlos_app      LOGIN PASSWORD '${APP_DB_PASSWORD}'      NOBYPASSRLS;

  -- Fase 1A / Alternativa B: role do modulo de autenticacao. Sem privilegio
  -- sobre tabela alguma por padrao -- a migration 0008 concede o minimo, e a
  -- 0010 falha o deploy se alguem conceder mais do que isso.
  CREATE ROLE vlos_auth     LOGIN PASSWORD '${AUTH_DB_PASSWORD}'     NOBYPASSRLS;

  GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO vlos_migrator, vlos_app, vlos_auth;

  -- migrator cria os objetos; app apenas usa
  ALTER DATABASE ${POSTGRES_DB} OWNER TO vlos_migrator;
  REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL

echo "[init] roles vlos_migrator, vlos_app e vlos_auth criadas"
