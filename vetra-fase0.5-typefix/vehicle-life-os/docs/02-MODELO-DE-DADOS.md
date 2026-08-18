# VEHICLE LIFE OS — Modelo de Dados

**Documento B / Primeira Entrega**
PostgreSQL 16 · DDL de referência (será convertido em migrations versionadas)

---

## 1. Princípios que o schema materializa

1. **Identidade do veículo é permanente; placa é atributo temporal.** (§7) Placa muda — conversão Mercosul, transferência entre estados, sinistro. VIN também pode ser remarcado. Por isso identificadores ficam em tabela própria, com validade.
2. **Fato ≠ quem registrou o fato.** (§8, §53) Separar permite anonimizar o proprietário sem destruir a história do veículo.
3. **Proveniência é obrigatória, não opcional.** (§6, §95) Colunas `NOT NULL`. Não existe caminho de código que insira um fato sem origem.
4. **Correção não sobrescreve.** (§4, §33) Correção cria nova versão e marca a anterior como superseded.
5. **Conhecimento do modelo ≠ histórico do veículo.** (§56) Schemas separados.

---

## 2. Organização em schemas

| Schema | Conteúdo |
|---|---|
| `identity` | usuários, credenciais, sessões, MFA, consentimentos |
| `vehicle` | veículo, identificadores, propriedade, eventos, odômetro, documentos |
| `knowledge` | catálogo (marca/modelo/versão), intervalos oficiais, componentes |
| `ops` | alertas, notificações, compartilhamentos, jobs |
| `ai` | conversas, mensagens, consumo, cache |
| `audit` | log auditável encadeado |

Separar em schemas (e não bancos) mantém integridade referencial e transação única, permitindo depois separar o que crescer demais.

---

## 3. Tipos e enums

```sql
create extension if not exists pgcrypto;
create extension if not exists btree_gist;

-- §6: níveis de confiabilidade
create type vehicle.provenance_type as enum (
  'VERIFIED',
  'PROFESSIONAL_REPORTED',
  'USER_REPORTED',
  'EXTERNAL_SOURCE',
  'SYSTEM_INFERRED',
  'UNVERIFIED'
);

create type vehicle.record_status as enum ('ACTIVE','SUPERSEDED','RETRACTED','PENDING_CONFIRMATION');
create type vehicle.identifier_kind as enum ('VIN','PLATE','RENAVAM','ENGINE_NUMBER','INTERNAL_FLEET_CODE');
create type vehicle.asset_class as enum ('CAR','MOTORCYCLE','PICKUP','SUV','LIGHT_COMMERCIAL','TRUCK','BUS','AGRICULTURAL','CONSTRUCTION','OTHER');
create type vehicle.usage_profile as enum ('URBAN','HIGHWAY','MIXED','SEVERE','PROFESSIONAL','DELIVERY','COMPETITION');
create type vehicle.ownership_role as enum ('OWNER','CO_OWNER','DRIVER','FLEET_MANAGER','WORKSHOP');
create type vehicle.claim_status as enum ('PENDING','VERIFIED','REJECTED','DISPUTED','REVOKED');
```

**Sobre o tipo de evento (§12):** é `text` referenciando `vehicle.event_type` (tabela), **não** enum. A §12 exige adicionar tipos sem mexer no banco; `ALTER TYPE ... ADD VALUE` é migração, tabela de catálogo é `INSERT`.

```sql
create table vehicle.event_type (
  code            text primary key,          -- 'OIL_CHANGE', 'TIRE_REPLACEMENT'
  category        text not null,             -- 'MAINTENANCE','OWNERSHIP','DOCUMENT','INCIDENT','FINANCIAL','TELEMETRY'
  applies_to      vehicle.asset_class[] not null default '{}',  -- vazio = todas
  payload_schema  jsonb not null,            -- JSON Schema que valida o payload
  label_pt_br     text not null,
  is_active       boolean not null default true,
  created_at      timestamptz not null default now()
);
```

O `payload_schema` é o que impede que "genérico" vire "bagunça": cada tipo valida seu próprio payload na aplicação **e** no banco (constraint via função `jsonb_matches_schema` do `pg_jsonschema`, quando disponível).

---

## 4. Núcleo: identidade do veículo

```sql
create table vehicle.vehicle (
  id                uuid primary key default gen_random_uuid(),
  asset_class       vehicle.asset_class not null,
  catalog_trim_id   uuid references knowledge.trim(id),   -- quando reconhecido no catálogo
  -- campos livres para quando o catálogo não cobre (importados, customizados)
  make_text         text,
  model_text        text,
  version_text      text,
  manufacture_year  smallint check (manufacture_year between 1900 and 2100),
  model_year        smallint check (model_year between 1900 and 2100),
  fuel              text,
  transmission      text,
  color             text,
  country_of_origin char(2),
  first_seen_at     timestamptz not null default now(),
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now(),
  deleted_at        timestamptz            -- §97 soft delete
);
```

Note o que **não** está aqui: proprietário, placa, chassi, quilometragem. Nenhum desses é atributo estável do veículo.

```sql
-- §7, §8: identificadores cifrados, com validade temporal
create table vehicle.vehicle_identifier (
  id             uuid primary key default gen_random_uuid(),
  vehicle_id     uuid not null references vehicle.vehicle(id),
  kind           vehicle.identifier_kind not null,
  value_hash     bytea not null,          -- HMAC-SHA256(pepper_app, normalize(valor)) — índice cego
  value_cipher   bytea not null,          -- AES-256-GCM, chave derivada por envelope (ver Doc C)
  value_masked   text not null,           -- 'ABC1D**' / '9BR***********123' para exibição
  valid_from     date not null default current_date,
  valid_to       date,
  provenance     vehicle.provenance_type not null,
  source_ref     text,
  created_at     timestamptz not null default now()
);

-- um mesmo identificador ativo não pode apontar para dois veículos
create unique index vehicle_identifier_active_uk
  on vehicle.vehicle_identifier (kind, value_hash)
  where valid_to is null;

create index vehicle_identifier_vehicle_ix on vehicle.vehicle_identifier (vehicle_id, kind);
```

Busca por placa = calcular HMAC e comparar igualdade. Um dump do banco sem o pepper (que fica fora do banco) não permite descobrir nem reverter placas.

---

## 5. Propriedade e acesso

```sql
-- §8, §9: Vehicle → Ownership → User
create table vehicle.ownership (
  id             uuid primary key default gen_random_uuid(),
  vehicle_id     uuid not null references vehicle.vehicle(id),
  user_id        uuid references identity.user(id),   -- null = proprietário histórico não usuário
  display_label  text,                                 -- 'Proprietário 1' após anonimização
  role           vehicle.ownership_role not null default 'OWNER',
  started_on     date,
  ended_on       date,
  city           text,
  state_uf       char(2),
  claim_status   vehicle.claim_status not null default 'PENDING',
  claim_evidence_document_id uuid,
  verified_at    timestamptz,
  verified_by    uuid,
  provenance     vehicle.provenance_type not null default 'USER_REPORTED',
  anonymized_at  timestamptz,
  created_at     timestamptz not null default now(),
  constraint ownership_period_valid check (ended_on is null or started_on is null or ended_on >= started_on)
);

-- impede dois proprietários VERIFICADOS simultâneos no mesmo período
create extension if not exists btree_gist;
alter table vehicle.ownership
  add constraint ownership_no_overlap
  exclude using gist (
    vehicle_id with =,
    daterange(started_on, coalesce(ended_on, 'infinity'::date), '[]') with &&
  ) where (role = 'OWNER' and claim_status = 'VERIFIED');
```

Essa constraint de exclusão é a defesa estrutural contra dois usuários "donos" do mesmo carro ao mesmo tempo — o banco recusa, não a aplicação.

```sql
-- tabela de acesso efetivo: usada por RLS e por autorização de serviço
create table vehicle.vehicle_access (
  vehicle_id   uuid not null references vehicle.vehicle(id),
  user_id      uuid not null references identity.user(id),
  scope        text not null,        -- 'OWNER','SHARED_MECHANIC','SHARED_BUYER','FLEET','ADMIN_GRANT'
  granted_at   timestamptz not null default now(),
  expires_at   timestamptz,
  revoked_at   timestamptz,
  granted_by   uuid,
  primary key (vehicle_id, user_id, scope)
);
create index vehicle_access_user_ix on vehicle.vehicle_access (user_id) where revoked_at is null;
```

---

## 6. O log de eventos (núcleo do produto)

```sql
create table vehicle.event (
  id                 uuid primary key default gen_random_uuid(),
  vehicle_id         uuid not null references vehicle.vehicle(id),
  event_type         text not null references vehicle.event_type(code),

  occurred_at        timestamptz not null,        -- quando aconteceu no mundo
  recorded_at        timestamptz not null default now(),  -- quando entrou no sistema
  occurred_precision text not null default 'DAY', -- 'DAY','MONTH','YEAR' — data aproximada é honesta
  odometer_km        integer check (odometer_km >= 0),

  payload            jsonb not null default '{}'::jsonb,

  -- §95 proveniência (obrigatória)
  provenance         vehicle.provenance_type not null,
  source_type        text not null,               -- 'MANUAL','OCR_INVOICE','NFE_KEY','WORKSHOP_API','TELEMETRY'
  source_ref         text,                        -- nº da OS, chave NF-e, id externo
  confidence         numeric(3,2) not null check (confidence between 0 and 1),
  recorded_by_user   uuid references identity.user(id),
  recorded_by_org    uuid references identity.organization(id),
  verified_at        timestamptz,
  verified_by        uuid,

  -- §4, §33 versionamento
  status             vehicle.record_status not null default 'ACTIVE',
  revision           integer not null default 1,
  root_event_id      uuid,                        -- primeira versão da cadeia
  supersedes_id      uuid references vehicle.event(id),
  correction_reason  text,
  content_hash       bytea not null,              -- sha256 do conteúdo canônico

  cost_amount        numeric(14,2),               -- §59
  cost_currency      char(3) default 'BRL',

  deleted_at         timestamptz
);

create index event_timeline_ix on vehicle.event (vehicle_id, occurred_at desc)
  where status = 'ACTIVE' and deleted_at is null;
create index event_type_ix     on vehicle.event (vehicle_id, event_type, occurred_at desc);
create index event_chain_ix    on vehicle.event (root_event_id, revision);
create index event_payload_gin on vehicle.event using gin (payload jsonb_path_ops);
```

**Regra de imutabilidade aplicada no banco, não só no código:**

```sql
create or replace function vehicle.forbid_event_mutation() returns trigger as $$
begin
  -- só transições de status/verificação são permitidas; conteúdo é imutável
  if (new.payload is distinct from old.payload)
     or (new.occurred_at is distinct from old.occurred_at)
     or (new.odometer_km is distinct from old.odometer_km)
     or (new.event_type is distinct from old.event_type)
     or (new.vehicle_id is distinct from old.vehicle_id) then
    raise exception 'Eventos sao imutaveis. Crie uma correcao (nova revisao).';
  end if;
  return new;
end $$ language plpgsql;

create trigger event_immutable before update on vehicle.event
  for each row execute function vehicle.forbid_event_mutation();

create rule event_no_delete as on delete to vehicle.event do instead nothing;
```

Corrigir um evento = inserir nova linha com `revision = anterior + 1`, `supersedes_id`, `correction_reason`, e `UPDATE` da anterior apenas para `status = 'SUPERSEDED'`. A timeline lê `status = 'ACTIVE'`; a auditoria lê a cadeia inteira. Isso responde literalmente à §4: dado original, dado corrigido, quem, quando, por quê, origem.

**Sobre particionamento:** não particionar agora. Com índice em `(vehicle_id, occurred_at)`, o Postgres atende dezenas de milhões de linhas confortavelmente. Quando passar de ~50M, particionar por `RANGE (recorded_at)` anual — a migração está prevista mas não deve ser antecipada.

---

## 7. Odômetro e detecção de inconsistência

```sql
create table vehicle.odometer_reading (
  id            uuid primary key default gen_random_uuid(),
  vehicle_id    uuid not null references vehicle.vehicle(id),
  event_id      uuid references vehicle.event(id),
  value_km      integer not null check (value_km >= 0),
  measured_at   timestamptz not null,
  provenance    vehicle.provenance_type not null,
  source_ref    text,
  document_id   uuid,
  recorded_by   uuid,
  status        vehicle.record_status not null default 'ACTIVE',
  created_at    timestamptz not null default now()
);
create index odometer_series_ix on vehicle.odometer_reading (vehicle_id, measured_at desc) where status = 'ACTIVE';

-- §14: anomalias registradas, nunca acusação automática
create table vehicle.anomaly (
  id             uuid primary key default gen_random_uuid(),
  vehicle_id     uuid not null references vehicle.vehicle(id),
  kind           text not null,      -- 'ODOMETER_REGRESSION','ODOMETER_IMPLAUSIBLE_RATE','DATE_INCONSISTENCY','DUPLICATE_EVENT'
  severity       text not null,      -- 'INFO','ATTENTION'
  related_ids    uuid[] not null,
  detected_at    timestamptz not null default now(),
  resolved_at    timestamptz,
  resolution     text,               -- 'CORRECTED','EXPLAINED','ACCEPTED','FALSE_POSITIVE'
  explanation    text                -- ex.: 'painel substituido', 'motor trocado'
);
```

A política de consistência (domínio puro, testável sem banco):

| Situação | Detecção | Mensagem ao usuário |
|---|---|---|
| Leitura menor que anterior | `value_km < max(anterior)` | "Encontramos uma inconsistência nos registros de quilometragem. Verifique as informações." (§14, literal) |
| Ritmo implausível | > 500 km/dia sustentado por > 7 dias | Atenção, com pedido de confirmação |
| Troca de painel | usuário informa | Cria marco de reset; leituras posteriores contam a partir dele |

Nunca a palavra "fraude". Nunca bloqueio automático. Anomalia é informação, não acusação.

---

## 8. Documentos (cofre)

```sql
create table vehicle.document (
  id                 uuid primary key default gen_random_uuid(),
  vehicle_id         uuid references vehicle.vehicle(id),
  owner_user_id      uuid not null references identity.user(id),
  kind               text not null,          -- 'INVOICE','SERVICE_ORDER','MANUAL','INSURANCE','PHOTO','CRLV','OTHER'
  storage_key        text not null unique,   -- nome aleatório, sem relação com o conteúdo
  original_filename  text,
  mime_detected      text not null,          -- detectado por magic bytes, não pela extensão
  size_bytes         bigint not null,
  sha256             bytea not null,
  scan_status        text not null default 'PENDING',  -- PENDING|CLEAN|INFECTED|ERROR
  scan_at            timestamptz,
  ocr_status         text not null default 'PENDING',
  contains_personal_data boolean not null default true,
  shareable          boolean not null default false,   -- §28: por padrão NÃO acompanha compartilhamento
  exif_stripped      boolean not null default false,
  created_at         timestamptz not null default now(),
  deleted_at         timestamptz
);
create index document_dedup_ix on vehicle.document (owner_user_id, sha256);

create table vehicle.event_document (
  event_id    uuid not null references vehicle.event(id),
  document_id uuid not null references vehicle.document(id),
  primary key (event_id, document_id)
);

-- extração antes da confirmação do usuário (§24)
create table vehicle.document_extraction (
  id             uuid primary key default gen_random_uuid(),
  document_id    uuid not null references vehicle.document(id),
  method         text not null,        -- 'NFE_KEY','QR','OCR_VISION','OCR_TESSERACT','MANUAL'
  raw_result     jsonb not null,
  fields         jsonb not null,       -- {date, total, cnpj, items[], odometer}
  field_confidence jsonb not null,     -- confiança por campo
  provider       text,
  cost_cents     integer,
  confirmed_at   timestamptz,
  confirmed_by   uuid,
  created_at     timestamptz not null default now()
);
```

`shareable = false` por padrão é a decisão de privacidade mais importante do schema: uma nota fiscal contém CPF do dono e CNPJ da oficina. O comprador recebe **o fato extraído**, não a imagem do documento — salvo escolha explícita.

---

## 9. Base de conhecimento (§56, §57) — separada do histórico

```sql
create table knowledge.make       (id uuid primary key, name text not null unique, country char(2));
create table knowledge.model      (id uuid primary key, make_id uuid not null references knowledge.make(id),
                                   name text not null, asset_class vehicle.asset_class not null,
                                   unique (make_id, name));
create table knowledge.trim (
  id uuid primary key, model_id uuid not null references knowledge.model(id),
  name text not null, model_year smallint not null,
  engine_code text, displacement_cc integer, fuel text, transmission text, body text,
  source text not null, imported_at timestamptz not null default now(),
  unique (model_id, name, model_year)
);

-- §16: intervalo oficial NUNCA existe sem fonte
create table knowledge.service_interval (
  id              uuid primary key default gen_random_uuid(),
  trim_id         uuid references knowledge.trim(id),
  model_id        uuid references knowledge.model(id),   -- quando vale para todas as versões
  item_code       text not null,           -- 'ENGINE_OIL','OIL_FILTER','BRAKE_FLUID','TIMING_BELT','CHAIN_KIT'
  interval_km     integer,
  interval_months integer,
  usage_profile   vehicle.usage_profile not null default 'MIXED',
  source_type     text not null,           -- 'OEM_MANUAL','OEM_SITE','PARTNER','ESTIMATE'
  source_citation text not null,           -- 'Manual do Proprietário Corolla 2022, pág. 312'
  source_url      text,
  curated_by      uuid not null,
  verified_at     timestamptz,
  confidence      numeric(3,2) not null,
  constraint interval_has_target check (trim_id is not null or model_id is not null),
  constraint interval_has_value  check (interval_km is not null or interval_months is not null)
);
```

`source_citation NOT NULL` é a implementação literal da §16. Não há como inserir uma recomendação sem declarar de onde ela veio; um dado marcado `ESTIMATE` chega à interface rotulado como estimativa.

---

## 10. Manutenção, alertas e compartilhamento

```sql
create table vehicle.maintenance_plan_item (
  id            uuid primary key default gen_random_uuid(),
  vehicle_id    uuid not null references vehicle.vehicle(id),
  item_code     text not null,
  interval_km   integer,
  interval_months integer,
  source        text not null,        -- 'KNOWLEDGE_BASE','USER_DEFINED','WORKSHOP'
  source_interval_id uuid references knowledge.service_interval(id),
  last_done_event_id uuid references vehicle.event(id),
  last_done_km  integer,
  last_done_at  date,
  next_due_km   integer,              -- projeção recalculada pelo worker
  next_due_at   date,
  projection_confidence numeric(3,2),
  is_active     boolean not null default true,
  unique (vehicle_id, item_code)
);

create table ops.alert (
  id           uuid primary key default gen_random_uuid(),
  vehicle_id   uuid not null references vehicle.vehicle(id),
  user_id      uuid not null references identity.user(id),
  kind         text not null,
  level        text not null,        -- 'INFO','RECOMMENDATION','ATTENTION','URGENT'  (§75)
  title        text not null,
  body         text,
  due_at       date,
  due_km       integer,
  source_item  uuid,
  state        text not null default 'OPEN',  -- OPEN|SNOOZED|DONE|DISMISSED
  snoozed_until timestamptz,
  created_at   timestamptz not null default now()
);

-- §28, §29: compartilhamento temporário com escopo
create table ops.share_grant (
  id            uuid primary key default gen_random_uuid(),
  vehicle_id    uuid not null references vehicle.vehicle(id),
  created_by    uuid not null references identity.user(id),
  token_hash    bytea not null unique,     -- sha256 do token; o token só existe no link
  scope         text not null,             -- 'MECHANIC','BUYER','PUBLIC'
  fields        jsonb not null,            -- whitelist explícita do que é exposto
  include_documents boolean not null default false,
  expires_at    timestamptz not null,
  max_views     integer,
  view_count    integer not null default 0,
  revoked_at    timestamptz,
  created_at    timestamptz not null default now()
);

create table ops.share_access_log (
  id         uuid primary key default gen_random_uuid(),
  grant_id   uuid not null references ops.share_grant(id),
  accessed_at timestamptz not null default now(),
  ip_hash    bytea,          -- IP nunca em claro (§87)
  user_agent_hash bytea
);
```

`fields` é whitelist, não blacklist. O que não estiver listado não é exposto — inclusive campos criados no futuro, que por definição não estarão em grants antigos.

---

## 11. Auditoria encadeada (§34, §51)

```sql
create table audit.log (
  id            bigserial primary key,
  occurred_at   timestamptz not null default now(),
  actor_user_id uuid,
  actor_type    text not null,        -- 'USER','ADMIN','SYSTEM','WORKSHOP'
  action        text not null,        -- 'VEHICLE_VIEW','DOCUMENT_DOWNLOAD','ADMIN_ACCESS_VEHICLE'
  object_type   text,
  object_id     uuid,
  reason        text,                 -- obrigatório para ações administrativas (§51)
  metadata      jsonb not null default '{}'::jsonb,
  ip_hash       bytea,
  prev_hash     bytea,
  entry_hash    bytea not null
);
```

`entry_hash = sha256(prev_hash || canonical_json(entrada))`. Alterar ou remover uma entrada quebra a cadeia de todas as seguintes, e a quebra é detectável por um job diário. A aplicação conecta com um role que tem **apenas `INSERT`** nesse schema — nem o código da API consegue `UPDATE` ou `DELETE` ali.

---

## 12. Row Level Security (§37, §38)

```sql
alter table vehicle.event enable row level security;
-- NAO usamos FORCE: ver AUD-05 em docs/06-AUDITORIA-FASE0.md.
-- vlos_app nunca e dona das tabelas, entao ENABLE ja a submete as policies;
-- FORCE quebraria as funcoes SECURITY DEFINER de login e cadastro.

create policy event_select on vehicle.event for select
using (
  exists (
    select 1 from vehicle.vehicle_access va
    where va.vehicle_id = vehicle.event.vehicle_id
      and va.user_id = current_setting('app.user_id', true)::uuid
      and va.revoked_at is null
      and (va.expires_at is null or va.expires_at > now())
  )
);

create policy event_insert on vehicle.event for insert
with check (
  exists (
    select 1 from vehicle.vehicle_access va
    where va.vehicle_id = vehicle.event.vehicle_id
      and va.user_id = current_setting('app.user_id', true)::uuid
      and va.scope in ('OWNER','FLEET')
      and va.revoked_at is null
  )
);
```

Toda transação da API executa `SET LOCAL app.user_id = $1` antes de qualquer query. O role da aplicação **não** tem `BYPASSRLS`. Consequência prática: mesmo que um controller esqueça um `where user_id = ...`, ou que exista uma SQL injection, o banco não devolve linhas de outro usuário. É a segunda camada da defesa em profundidade — a primeira é a autorização no serviço, descrita no Documento C.

---

## 13. Projeções de leitura

Consultas de timeline e passaporte não varrem o log. São materializadas e atualizadas pelo worker a cada evento:

```sql
create materialized view vehicle.passport_summary as
select v.id as vehicle_id,
       count(*) filter (where e.status='ACTIVE')                                as event_count,
       count(*) filter (where e.provenance='VERIFIED')                          as verified_count,
       count(*) filter (where e.provenance='USER_REPORTED')                     as user_count,
       count(*) filter (where e.provenance='PROFESSIONAL_REPORTED')             as professional_count,
       max(e.odometer_km)                                                       as max_odometer_km,
       min(e.occurred_at)                                                       as history_starts_at
from vehicle.vehicle v
left join vehicle.event e on e.vehicle_id = v.id and e.deleted_at is null
group by v.id;
```

Para o MVP, `REFRESH MATERIALIZED VIEW CONCURRENTLY` agendado + invalidação por evento é suficiente. Quando o volume exigir, vira tabela de projeção incremental.

---

## 14. Diagrama de relacionamento (resumo)

```
identity.user ─┬─< vehicle.ownership >─┬─ vehicle.vehicle ─┬─< vehicle.vehicle_identifier
               │                       │                   ├─< vehicle.event ─┬─< vehicle.event_document
               ├─< vehicle.vehicle_access                   │                  └─ (revision chain: supersedes_id)
               ├─< vehicle.document >──────────────────────┤
               │        └─< vehicle.document_extraction     ├─< vehicle.odometer_reading
               ├─< ops.share_grant ─< ops.share_access_log  ├─< vehicle.anomaly
               └─< ai.conversation                          └─< vehicle.maintenance_plan_item
                                                                       │
knowledge.make ─< knowledge.model ─< knowledge.trim ─< knowledge.service_interval
                                            │
                                            └──────── vehicle.vehicle.catalog_trim_id
```

---

## 15. Como o schema responde às regras do briefing

| Regra | Onde está implementada |
|---|---|
| §4 não apagar histórico | trigger de imutabilidade + rule `no_delete` + cadeia de revisões |
| §6 níveis de confiabilidade | enum `provenance_type`, coluna `NOT NULL` em event, identifier, ownership |
| §7 identidade permanente | `vehicle` sem placa; `vehicle_identifier` com validade |
| §8 privacidade da identidade | HMAC + AES-GCM + `value_masked` |
| §9/§53 dados de terceiros | `ownership.display_label` + `anonymized_at` |
| §12 eventos extensíveis | `event_type` como tabela + `payload` jsonb validado por JSON Schema |
| §14 inconsistência | `anomaly`, sem bloqueio nem acusação |
| §16 não inventar intervalos | `service_interval.source_citation NOT NULL` |
| §29 privacidade por camadas | `share_grant.fields` whitelist |
| §33 event sourcing | log append-only + projeções |
| §34/§51 auditoria | `audit.log` com hash encadeado e role insert-only |
| §37/§38 zero trust e isolamento | RLS forçada + `app.user_id` por transação |
| §95/§96 proveniência | `source_type`, `source_ref`, `confidence`, `verified_by` em cada fato |
| §97 soft delete | `deleted_at` + processo separado de anonimização |
