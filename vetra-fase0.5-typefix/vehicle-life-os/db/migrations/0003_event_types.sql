-- =============================================================================
-- 0003_event_types
-- Catalogo de tipos de evento.
-- Briefing secao 12: novos tipos devem entrar SEM alterar o banco.
-- Por isso e tabela, nao enum: adicionar tipo e INSERT, nao migration.
-- =============================================================================

CREATE TABLE vehicle.event_type (
  code            text PRIMARY KEY,
  category        text NOT NULL,      -- MAINTENANCE | OWNERSHIP | DOCUMENT | INCIDENT | FINANCIAL | TELEMETRY | ODOMETER
  label_pt_br     text NOT NULL,
  applies_to      vehicle.asset_class[] NOT NULL DEFAULT '{}',  -- vazio = todas as classes
  payload_schema  jsonb NOT NULL DEFAULT '{"type":"object"}'::jsonb,
  affects_odometer boolean NOT NULL DEFAULT false,
  is_cost_bearing boolean NOT NULL DEFAULT false,
  is_active       boolean NOT NULL DEFAULT true,
  sort_order      integer NOT NULL DEFAULT 100,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX event_type_category_ix ON vehicle.event_type (category) WHERE is_active;

COMMENT ON COLUMN vehicle.event_type.payload_schema IS
  'JSON Schema validado na camada de aplicacao antes do INSERT. Impede que "generico" vire "sem estrutura".';
