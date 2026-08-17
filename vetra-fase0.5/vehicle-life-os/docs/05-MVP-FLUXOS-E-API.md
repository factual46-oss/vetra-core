# VEHICLE LIFE OS — MVP, Fluxos, API e Plano de Implementação

**Documentos C, G, H, I / Primeira Entrega**

---

## 1. Escopo do MVP

Os doze critérios da §107, mais o que sustenta a credibilidade da plataforma (auditoria, backup, admin).

| # | Capacidade | Entra no MVP | Observação |
|---|---|---|---|
| 1 | Conta, login, MFA | Sim | MFA opcional para usuário, obrigatório para admin |
| 2 | Adicionar veículo (claim) | Sim | Com verificação; sem verificação o histórico prévio não é exibido |
| 3 | Garagem | Sim | §73 |
| 4 | Passaporte Digital | Sim | §10, sem score numérico |
| 5 | Timeline | Sim | §11 |
| 6 | Eventos e manutenção | Sim | 12 tipos iniciais, extensíveis por dado |
| 7 | Quilometragem + inconsistência | Sim | §13, §14 |
| 8 | Documentos | Sim | Com antivírus, EXIF stripping |
| 9 | OCR / extração | Sim | Cascata chave NF-e → visão → manual |
| 10 | Alertas | Sim | Push web + e-mail; WhatsApp depois |
| 11 | Vehicle AI | Sim | Somente sobre dados existentes, com fonte |
| 12 | Compartilhar relatório | Sim | Link temporário com escopo |
| 13 | Histórico auditável | Sim | Base de tudo |
| 14 | Admin | Sim | Métricas, usuários, curadoria, moderação |
| 15 | Backup + restore testado | Sim | Antes de qualquer usuário real |
| — | Score de histórico | **Não** | Sem dados para calibrar; métricas coletadas desde já |
| — | Perfil de oficina | **Não** | Fase 2 |
| — | Transferência de veículo | **Não** | Modelada, implementada na fase 2 |
| — | Diagnóstico, recall, TCO, frota, marketplace | **Não** | Futuro explícito no briefing |

---

## 2. Fluxos principais

### 2.1 Onboarding (§76)

```
Criar conta (e-mail + senha) → verificar e-mail
   ↓
Adicionar veículo:
   ├─ informar placa OU chassi
   ├─ sistema tenta reconhecer no catálogo → usuário confirma marca/modelo/ano/versão
   ├─ [não existe na base]  → cria vehicle + ownership(PENDING) + identifier
   └─ [já existe na base]   → cria ownership(PENDING). Resposta ao usuário é IDÊNTICA
                              nos dois casos. Nenhum dado prévio é exibido.
   ↓
Informar quilometragem atual  → primeiro odometer_reading (USER_REPORTED)
   ↓
Adicionar primeira manutenção ou documento  (pode pular)
   ↓
[opcional] Verificar propriedade: enviar CRLV → fila de verificação
   ↓
Passaporte Digital gerado
   ↓
"Seu veículo agora tem uma memória digital."
```

O ponto delicado, que a maioria dos produtos erra: **o passo de reconhecimento não pode revelar nada**. Se o sistema responde "encontramos um Corolla 2022 prata com 72.430 km" para quem digitou uma placa qualquer, o produto virou ferramenta de consulta de placa alheia. A confirmação é do usuário para o sistema, não do sistema para o usuário.

### 2.2 Registrar manutenção com documento

```
Usuário fotografa a nota
   ↓
Upload → validação (magic bytes, tamanho) → storage com chave aleatória → job
   ↓
Worker: ClamAV → strip EXIF → busca QR/código de barras
   ├─ chave NF-e (44 dígitos) encontrada → parser determinístico
   │     → emitente, data, valor com confiança ALTA (0,95)
   └─ sem chave → OCR/visão → campos com confiança POR CAMPO
   ↓
Usuário revisa a tela de confirmação (campos incertos destacados)
   ↓
Confirma → cria vehicle.event
             provenance = USER_REPORTED (confirmado pelo usuário)
             source_type = 'NFE_KEY' | 'OCR_VISION'
             confidence  = herdada da extração
   ↓
Se a nota traz KM → odometer_reading → política de consistência
   ↓
Recalcula plano de manutenção → gera/atualiza alertas
```

Nada entra no histórico sem o "confirmar". A IA propõe; o usuário decide. É o que a §24 pede e o que a §108 exige.

### 2.3 Correção de evento (§4)

```
Usuário edita um evento
   ↓
Sistema pede o motivo (obrigatório)
   ↓
INSERT nova revisão (revision+1, supersedes_id, correction_reason, mesmo root_event_id)
UPDATE anterior → status = SUPERSEDED
INSERT audit.log
   ↓
Timeline mostra a versão atual, com marcador "corrigido"
   → toque revela: valor original, valor novo, quem, quando, por quê
```

### 2.4 Compartilhamento para venda (§28, §63)

```
Proprietário escolhe escopo (MECÂNICO | COMPRADOR | PÚBLICO)
   ↓
Seleciona o que expor (whitelist de campos; documentos desmarcados por padrão)
   ↓
Define validade (padrão 7 dias) e limite de visualizações
   ↓
Sistema gera token de 32 bytes → guarda só o sha256 → devolve link + QR
   ↓
Visitante abre → valida token, validade, revogação, contador
   → renderiza SOMENTE os campos da whitelist
   → registra acesso (IP hasheado)
   ↓
Proprietário vê quantas vezes foi acessado e pode revogar a qualquer momento
```

Nunca expostos: CPF, endereço, telefone, documentos pessoais, identidade de proprietários anteriores.

### 2.5 Vehicle AI (§18)

```
Pergunta do usuário
   ↓
Guard: orçamento, rate limit, cache
   ↓
Recuperação de contexto por ferramentas com escopo do usuário
   (get_vehicle_summary, list_events, get_maintenance_status, get_costs)
   ↓
Prompt = pergunta + fatos recuperados, cada um com proveniência
   ↓
Resposta com citação da origem de cada afirmação
   ↓
Sem dado suficiente → "Não tenho dados suficientes para afirmar isso."
   ↓
Registra em ai.usage (tokens, custo, latência)
```

---

## 3. API v1 (§79, §80)

Base: `https://api.exemplo.com.br/api/v1`. Autenticação por Bearer (mobile/parceiros) ou cookie httpOnly via BFF (web). Contratos definidos em Zod no pacote `contracts`, com OpenAPI gerado a partir deles — uma fonte só, sem documentação que envelhece.

```
AUTENTICAÇÃO
POST   /auth/register
POST   /auth/login
POST   /auth/refresh
POST   /auth/logout
POST   /auth/password-reset            POST /auth/password-reset/confirm
POST   /auth/mfa/enroll                POST /auth/mfa/verify
GET    /auth/sessions                  DELETE /auth/sessions/:id

VEÍCULOS
GET    /vehicles                        # garagem do usuário
POST   /vehicles                        # claim
GET    /vehicles/:id
PATCH  /vehicles/:id                    # só atributos descritivos
DELETE /vehicles/:id                    # soft delete do vínculo, não do histórico
POST   /vehicles/:id/claim/verify       # envio de evidência
GET    /vehicles/:id/passport
GET    /vehicles/:id/timeline?cursor=&types=&from=&to=

EVENTOS
POST   /vehicles/:id/events
GET    /vehicles/:id/events/:eventId
POST   /vehicles/:id/events/:eventId/corrections   # nunca PUT: correção é criação
GET    /vehicles/:id/events/:eventId/history        # cadeia de revisões
POST   /vehicles/:id/events/:eventId/retract
GET    /event-types

QUILOMETRAGEM
POST   /vehicles/:id/odometer
GET    /vehicles/:id/odometer
GET    /vehicles/:id/anomalies
POST   /vehicles/:id/anomalies/:anomalyId/resolve

DOCUMENTOS
POST   /vehicles/:id/documents          # multipart
GET    /vehicles/:id/documents
GET    /documents/:id/download          # → URL pré-assinada de 60s
GET    /documents/:id/extraction
POST   /documents/:id/extraction/confirm
DELETE /documents/:id

MANUTENÇÃO
GET    /vehicles/:id/maintenance        # itens, próximos vencimentos, fonte de cada intervalo
POST   /vehicles/:id/maintenance/items  # plano definido pelo usuário
PATCH  /vehicles/:id/maintenance/items/:itemId
PUT    /vehicles/:id/usage-profile

ALERTAS
GET    /alerts                          POST /alerts/:id/snooze
POST   /alerts/:id/dismiss              PUT  /me/notification-preferences

COMPARTILHAMENTO
POST   /vehicles/:id/share              GET  /vehicles/:id/share
DELETE /share/:grantId                  GET  /public/share/:token   (sem autenticação)
GET    /vehicles/:id/report             # PDF gerado por worker

IA
POST   /ai/conversations                POST /ai/conversations/:id/messages
GET    /ai/usage

CONTA / LGPD
GET    /me                              PATCH /me
POST   /me/export                       # portabilidade
DELETE /me                              # exclusão com anonimização
GET    /me/consents                     PUT   /me/consents

ADMIN  (/admin/*, permissões granulares, motivo obrigatório, tudo auditado)
GET    /admin/metrics                   GET  /admin/users
POST   /admin/users/:id/block           GET  /admin/audit
GET    /admin/knowledge/intervals       POST /admin/knowledge/intervals
GET    /admin/claims/pending            POST /admin/claims/:id/decide
```

**Convenções:** paginação por cursor (nunca offset em tabela grande); `Idempotency-Key` em POST que cria evento ou documento; erros no formato RFC 7807 com `traceId`; versionamento no caminho, com política de depreciação de 6 meses.

---

## 4. Interface — princípios (§72–§75)

- **Garagem** como tela inicial: cartão por veículo com foto, KM e um único indicador de estado (🟢 em dia / 🟡 atenção / 🔴 urgente).
- **"O que precisa da minha atenção?"** logo abaixo, no máximo 4 itens. Zero pendências é um estado válido e deve ser bonito, não uma tela vazia.
- **Quatro níveis visuais distintos** (informação / recomendação / atenção / urgência), com vermelho reservado ao que é realmente urgente. Nunca vermelho para "revisão em 800 km".
- **Proveniência visível sem poluir:** cada fato tem um ícone discreto que, ao toque, revela origem, data e documento. Essa é a materialização da §96 na interface — e é o detalhe que faz o produto parecer sério.
- Estados de carregamento e erro são reais. Nenhum botão inerte, nenhum dado fictício (§108).

---

## 5. Testes (§81)

| Camada | Cobertura pretendida | Foco |
|---|---|---|
| Unitários (domínio) | > 90% | Política de odômetro, cálculo de proveniência, motor de manutenção, whitelist de compartilhamento |
| Integração (com Postgres real via Testcontainers) | Todos os repositórios | RLS, triggers de imutabilidade, constraint de sobreposição de propriedade |
| API | Todas as rotas | Contrato, validação, autorização, paginação |
| Segurança | Obrigatória | Suíte do Documento C — IDOR, RLS, enumeração, upload, share, IA |
| E2E (Playwright) | Fluxos críticos | Onboarding, nota→evento, correção, compartilhamento |
| Carga (k6) | Antes do lançamento | Timeline com 10.000 eventos, 100 uploads simultâneos |

Nada de banco em memória para testar repositório: RLS e triggers só existem no PostgreSQL de verdade. Testar contra SQLite seria testar outro sistema.

---

## 6. Plano de implementação

Cada fase termina com algo demonstrável e implantado. Nenhuma fase termina com "faltou integrar".

| Fase | Entrega | Fim quando |
|---|---|---|
| **0 — Fundação** | Monorepo, Docker dev, CI, migrations base, health check, logs, seeds | `docker compose up` sobe tudo e o CI está verde |
| **1 — Identidade** | Cadastro, login, refresh rotativo, MFA, sessões, rate limit, auditoria | Suíte de segurança de auth passando |
| **2 — Veículo** | Claim, identificadores cifrados, garagem, catálogo mínimo, RLS ativa | Teste "A não acessa veículo de B" passa nos três níveis |
| **3 — Núcleo de eventos** | Log append-only, correções, timeline, odômetro, anomalias, passaporte | Corrigir um evento preserva e exibe a versão anterior |
| **4 — Documentos** | Upload, antivírus, EXIF, download assinado, vínculo com evento | Suíte de upload malicioso passando |
| **5 — Extração** | Chave NF-e, OCR de visão, tela de confirmação, controle de custo | Nota fiscal real vira evento após confirmação |
| **6 — Manutenção e alertas** | Intervalos com fonte, motor de projeção, alertas, e-mail e push | Nenhuma recomendação exibida sem origem declarada |
| **7 — IA** | Vehicle AI com ferramentas, guardrails, orçamento, citação de fonte | Teste de prompt injection não vaza dado alheio |
| **8 — Compartilhamento** | Escopos, link temporário, QR, relatório PDF, log de acesso | Campo fora da whitelist não aparece, comprovado por teste |
| **9 — Admin e operação** | Painel, permissões granulares, curadoria, Prometheus/Grafana | Alerta real disparando |
| **10 — Produção** | Deploy, TLS, backup, **restore testado**, runbook, pentest | Restauração completa executada e cronometrada |

Fases 0–3 são a espinha dorsal: se estiverem certas, o resto é acréscimo. Se estiverem erradas, nada depois conserta.

---

## 7. Critérios de aceite do MVP

O MVP está pronto quando, com dados reais e sem nenhuma simulação:

1. Um usuário cria conta, ativa MFA e faz login em outro dispositivo.
2. Cadastra um veículo; **um segundo usuário cadastra a mesma placa e não vê nada do primeiro**.
3. Registra KM; ao registrar um valor menor, recebe o aviso de inconsistência — sem acusação.
4. Fotografa uma nota fiscal real; os campos são extraídos, ele corrige um deles e confirma; vira evento com a origem correta.
5. Corrige o evento; a versão anterior continua consultável, com autor e motivo.
6. Vê a timeline, o passaporte e a origem de cada dado.
7. Recebe um alerta de manutenção **cuja recomendação exibe a fonte**.
8. Pergunta à IA "quanto já gastei com manutenção?" e recebe resposta correta com as fontes; pergunta algo sem dado e recebe "Não tenho dados suficientes para afirmar isso."
9. Gera link de venda com validade de 7 dias; abre em janela anônima e confirma que nenhum dado pessoal aparece; revoga e o link morre.
10. Toda a suíte de segurança passa; a cadeia de hash da auditoria está íntegra.
11. Uma restauração completa do banco foi executada e cronometrada dentro do RTO.
12. Nenhum botão inerte, nenhum dado fictício, nenhum erro escondido.

---

## 8. O que fica pronto para o futuro sem estar implementado

| Ambição do briefing | O que já existe na arquitetura |
|---|---|
| Oficinas e PROFESSIONAL_VERIFIED (§25–26) | `identity.organization`, `event.recorded_by_org`, `provenance = PROFESSIONAL_REPORTED` |
| Transferência (§64) | `ownership` temporal + `anonymized_at` + evento de mudança de propriedade |
| Recall (§62) | `event_type` extensível + `EXTERNAL_SOURCE` + `source_ref` |
| Frotas e caminhões (§69–70) | `asset_class`, `ownership_role = FLEET_MANAGER`, odômetro/horímetro como tipos de leitura |
| Motos (§71) | `event_type.applies_to` + itens específicos (`CHAIN_KIT`) na base de conhecimento |
| Telemetria (§99) | `source_type = 'TELEMETRY'`, ingestão por worker, mesmo log de eventos |
| API para parceiros (§101) | API já é a única interface; falta apenas OAuth de terceiros e escopos |
| Inteligência agregada (§58, §100) | Schema `analytics` separado, alimentado por ETL, com limiar estatístico mínimo |
| Digital twin (§98) | O log de eventos com proveniência **é** o digital twin em forma de dados |

Nenhuma dessas exige migração destrutiva. Essa é a definição prática de "nascer pequeno com arquitetura que permite crescer".
