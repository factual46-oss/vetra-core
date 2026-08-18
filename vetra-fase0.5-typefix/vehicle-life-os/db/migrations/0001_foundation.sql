-- =============================================================================
-- 0001_foundation
-- Extensoes, schemas, tipos e utilitarios. Nenhuma tabela de dominio aqui.
-- Referencia: Documento 02 (Modelo de Dados), secoes 2 e 3.
--
-- AUD-01 (CRITICO, corrigido): as extensoes ficavam em `public`, mas o script
-- de init executa REVOKE ALL ON SCHEMA public FROM PUBLIC. Como vlos_app nunca
-- recebe USAGE em `public`, toda chamada a digest() -- inclusive a do trigger
-- que sela audit.log -- falharia em runtime com "permission denied for schema
-- public". Extensoes passam a viver em schema proprio e sao sempre qualificadas.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS extensions;

CREATE EXTENSION IF NOT EXISTS pgcrypto   WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS btree_gist WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS citext     WITH SCHEMA extensions;

CREATE SCHEMA IF NOT EXISTS identity;
CREATE SCHEMA IF NOT EXISTS vehicle;
CREATE SCHEMA IF NOT EXISTS knowledge;
CREATE SCHEMA IF NOT EXISTS ops;
CREATE SCHEMA IF NOT EXISTS ai;
CREATE SCHEMA IF NOT EXISTS audit;

-- Sessoes novas enxergam as extensoes sem precisar qualificar tipos.
-- Nao substitui a qualificacao explicita dentro de funcoes: search_path e
-- estado de sessao e nao pode ser base de garantia de seguranca.
DO $do$
BEGIN
  EXECUTE format('ALTER DATABASE %I SET search_path = "$user", public, extensions', current_database());
END
$do$;

-- Vale tambem para a sessao corrente (migrations seguintes deste mesmo lote).
SET search_path = public, extensions;

-- -----------------------------------------------------------------------------
-- Tipos de dominio
-- -----------------------------------------------------------------------------

-- Briefing secao 6: niveis de confiabilidade. Ordem = precedencia (maior primeiro).
CREATE TYPE vehicle.provenance_type AS ENUM (
  'VERIFIED',
  'PROFESSIONAL_REPORTED',
  'USER_REPORTED',
  'EXTERNAL_SOURCE',
  'SYSTEM_INFERRED',
  'UNVERIFIED'
);

CREATE TYPE vehicle.record_status AS ENUM (
  'PENDING_CONFIRMATION',
  'ACTIVE',
  'SUPERSEDED',
  'RETRACTED'
);

CREATE TYPE vehicle.identifier_kind AS ENUM (
  'VIN', 'PLATE', 'RENAVAM', 'ENGINE_NUMBER', 'INTERNAL_FLEET_CODE'
);

CREATE TYPE vehicle.asset_class AS ENUM (
  'CAR', 'MOTORCYCLE', 'PICKUP', 'SUV', 'LIGHT_COMMERCIAL',
  'TRUCK', 'BUS', 'AGRICULTURAL', 'CONSTRUCTION', 'OTHER'
);

CREATE TYPE vehicle.usage_profile AS ENUM (
  'URBAN', 'HIGHWAY', 'MIXED', 'SEVERE', 'PROFESSIONAL', 'DELIVERY', 'COMPETITION'
);

CREATE TYPE vehicle.ownership_role AS ENUM (
  'OWNER', 'CO_OWNER', 'DRIVER', 'FLEET_MANAGER', 'WORKSHOP'
);

CREATE TYPE vehicle.claim_status AS ENUM (
  'PENDING', 'VERIFIED', 'REJECTED', 'DISPUTED', 'REVOKED'
);

-- -----------------------------------------------------------------------------
-- Utilitarios
--
-- AUD-02 (ALTO, corrigido): funcoes agora tem search_path fixado. Sem isso,
-- uma sessao que altere search_path poderia fazer a funcao resolver um objeto
-- diferente do esperado. Custa uma linha e fecha uma classe inteira de ataque.
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ops.touch_updated_at() RETURNS trigger AS $fn$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$fn$ LANGUAGE plpgsql SET search_path = pg_catalog, public, extensions;

-- Identidade do usuario da requisicao. Definida por set_config('app.user_id', ..., true)
-- no inicio de cada transacao da API. Usada por TODAS as policies de RLS.
--
-- Contrato: retorna NULL quando o contexto nao foi definido. As policies usam
-- igualdade contra este retorno, e comparacao com NULL e sempre falsa --
-- ou seja, ausencia de contexto = nenhuma linha visivel (fail-closed).
CREATE OR REPLACE FUNCTION ops.current_user_id() RETURNS uuid AS $fn$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid;
$fn$ LANGUAGE sql STABLE SET search_path = pg_catalog, public, extensions;

COMMENT ON FUNCTION ops.current_user_id() IS
  'NULL quando app.user_id nao foi definido. Policies falham fechado: sem contexto, zero linhas.';
