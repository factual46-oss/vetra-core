-- =============================================================================
-- Seed: tipos de evento iniciais (briefing secao 12).
-- Idempotente: pode rodar quantas vezes for necessario.
-- Adicionar um tipo novo depois = novo arquivo de seed, nunca migration.
-- =============================================================================

INSERT INTO vehicle.event_type
  (code, category, label_pt_br, applies_to, affects_odometer, is_cost_bearing, sort_order, payload_schema)
VALUES
  ('PURCHASE',          'OWNERSHIP',   'Compra',                  '{}', true,  true,  10,
   '{"type":"object","properties":{"seller_type":{"enum":["DEALER","PRIVATE","AUCTION"]},"price":{"type":"number"}}}'),
  ('SALE',              'OWNERSHIP',   'Venda',                   '{}', true,  false, 11,
   '{"type":"object","properties":{"price":{"type":"number"}}}'),
  ('SCHEDULED_SERVICE', 'MAINTENANCE', 'Revisão',                 '{}', true,  true,  20,
   '{"type":"object","properties":{"service_plan":{"type":"string"},"items":{"type":"array","items":{"type":"string"}},"workshop_name":{"type":"string"}}}'),
  ('OIL_CHANGE',        'MAINTENANCE', 'Troca de óleo',           '{}', true,  true,  21,
   '{"type":"object","properties":{"oil_spec":{"type":"string"},"oil_brand":{"type":"string"},"volume_liters":{"type":"number"},"filter_changed":{"type":"boolean"}}}'),
  ('FILTER_CHANGE',     'MAINTENANCE', 'Troca de filtro',         '{}', true,  true,  22,
   '{"type":"object","properties":{"filter_types":{"type":"array","items":{"enum":["OIL","AIR","CABIN","FUEL"]}}}}'),
  ('TIRE_SERVICE',      'MAINTENANCE', 'Pneus',                   '{}', true,  true,  23,
   '{"type":"object","properties":{"action":{"enum":["REPLACE","ROTATE","ALIGN","BALANCE","REPAIR"]},"brand":{"type":"string"},"size":{"type":"string"},"positions":{"type":"array","items":{"type":"string"}}}}'),
  ('BATTERY_SERVICE',   'MAINTENANCE', 'Bateria',                 '{}', true,  true,  24,
   '{"type":"object","properties":{"brand":{"type":"string"},"capacity_ah":{"type":"number"},"warranty_months":{"type":"integer"}}}'),
  ('BRAKE_SERVICE',     'MAINTENANCE', 'Freios',                  '{}', true,  true,  25,
   '{"type":"object","properties":{"components":{"type":"array","items":{"enum":["PADS_FRONT","PADS_REAR","DISCS_FRONT","DISCS_REAR","FLUID","SHOES"]}}}}'),
  ('SUSPENSION_SERVICE','MAINTENANCE', 'Suspensão',               '{}', true,  true,  26, '{"type":"object"}'),
  ('ENGINE_SERVICE',    'MAINTENANCE', 'Motor',                   '{}', true,  true,  27, '{"type":"object"}'),
  ('TRANSMISSION_SERVICE','MAINTENANCE','Câmbio',                 '{}', true,  true,  28, '{"type":"object"}'),
  ('ELECTRICAL_SERVICE','MAINTENANCE', 'Elétrica',                '{}', true,  true,  29, '{"type":"object"}'),
  ('BODYWORK',          'MAINTENANCE', 'Funilaria',               '{}', true,  true,  30, '{"type":"object"}'),
  ('PAINT',             'MAINTENANCE', 'Pintura',                 '{}', true,  true,  31, '{"type":"object"}'),
  ('CHAIN_KIT_SERVICE', 'MAINTENANCE', 'Relação (corrente/coroa/pinhão)',
                                                    '{MOTORCYCLE}', true,  true,  32,
   '{"type":"object","properties":{"action":{"enum":["LUBRICATE","ADJUST","REPLACE"]},"components":{"type":"array","items":{"enum":["CHAIN","FRONT_SPROCKET","REAR_SPROCKET"]}}}}'),
  ('GENERIC_MAINTENANCE','MAINTENANCE','Manutenção',              '{}', true,  true,  33, '{"type":"object"}'),
  ('DECLARED_INCIDENT', 'INCIDENT',    'Acidente declarado',      '{}', true,  false, 40,
   '{"type":"object","properties":{"severity":{"enum":["MINOR","MODERATE","SEVERE"]},"description":{"type":"string"},"insurance_claim":{"type":"boolean"}}}'),
  ('INSPECTION',        'DOCUMENT',    'Inspeção',                '{}', true,  true,  50, '{"type":"object"}'),
  ('RECALL',            'DOCUMENT',    'Recall',                  '{}', false, false, 51,
   '{"type":"object","properties":{"campaign_code":{"type":"string"},"status":{"enum":["ANNOUNCED","DONE","NOT_APPLICABLE"]}}}'),
  ('INSURANCE',         'FINANCIAL',   'Seguro',                  '{}', false, true,  52,
   '{"type":"object","properties":{"insurer":{"type":"string"},"policy_ends_on":{"type":"string","format":"date"}}}'),
  ('DOCUMENTATION',     'DOCUMENT',    'Documentação',            '{}', false, true,  53, '{"type":"object"}'),
  ('MODIFICATION',      'MAINTENANCE', 'Modificação',             '{}', true,  true,  54, '{"type":"object"}'),
  ('REFUELING',         'FINANCIAL',   'Abastecimento',           '{}', true,  true,  60,
   '{"type":"object","properties":{"fuel":{"enum":["GASOLINE","ETHANOL","DIESEL","CNG","ELECTRIC"]},"liters":{"type":"number"},"price_per_unit":{"type":"number"},"full_tank":{"type":"boolean"}}}'),
  ('ODOMETER_READING',  'ODOMETER',    'Quilometragem',           '{}', true,  false, 70, '{"type":"object"}'),
  ('OTHER',             'MAINTENANCE', 'Outro',                   '{}', false, false, 99, '{"type":"object"}')
ON CONFLICT (code) DO UPDATE SET
  category         = EXCLUDED.category,
  label_pt_br      = EXCLUDED.label_pt_br,
  applies_to       = EXCLUDED.applies_to,
  payload_schema   = EXCLUDED.payload_schema,
  affects_odometer = EXCLUDED.affects_odometer,
  is_cost_bearing  = EXCLUDED.is_cost_bearing,
  sort_order       = EXCLUDED.sort_order;
