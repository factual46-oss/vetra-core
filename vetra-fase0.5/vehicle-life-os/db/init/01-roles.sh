#!/bin/sh
set -e

# Criacao idempotente das roles de aplicacao e autenticacao
psql "$DATABASE_URL" <<-EOSQL
  DO \$\$
  BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'vlos_app') THEN
      CREATE ROLE vlos_app WITH LOGIN PASSWORD 'vetra_password';
    END IF;

    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'vlos_auth') THEN
      CREATE ROLE vlos_auth WITH LOGIN PASSWORD 'vetra_password';
    END IF;
  END
  \$\$;
EOSQL
