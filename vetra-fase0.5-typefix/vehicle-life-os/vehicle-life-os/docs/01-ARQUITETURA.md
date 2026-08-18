# VEHICLE LIFE OS — Arquitetura

**Documento A / Primeira Entrega**
Versão 0.1 — 15/08/2026
Status: proposta para aprovação (nenhuma linha de código escrita ainda, conforme §109)

---

## 1. Leitura do briefing: o que realmente está sendo construído

O briefing tem 112 seções. Se tratadas como requisitos simultâneos, representam de 18 a 30 meses de trabalho de uma equipe. Tratadas corretamente, elas se dividem em duas categorias muito diferentes:

| Categoria | O que é | Quando resolver |
|---|---|---|
| **Restrições estruturais** | Decisões que, se erradas no dia 1, exigem reescrever o sistema depois: identidade do veículo, proveniência do dado, imutabilidade do histórico, isolamento de dados, separação veículo↔proprietário, API-first | **Agora, na arquitetura** |
| **Funcionalidades** | Marketplace, frotas, telemetria, recall, TCO, comparação, IA preditiva, caminhões | **Depois — só não podem ser bloqueadas** |

Este documento resolve a primeira coluna e mostra por que a segunda continua possível.

**A tese central da arquitetura:** o produto não é o app. O produto é um **log de eventos com proveniência auditável, ancorado numa identidade de veículo estável**. Tudo o mais — timeline, passaporte, score, IA, relatório de venda — é *projeção de leitura* sobre esse log. Isso é o que permite que "o veículo mude de dono e a história continue".

---

## 2. Os cinco riscos que definem o projeto

Estes são os riscos que, na minha avaliação, matam o produto se não forem endereçados na arquitetura. Estão ordenados por gravidade.

### RISCO 1 — Enumeração de veículos (crítico, existencial)

O conceito "histórico sobrevive à troca de dono" exige que o veículo tenha **identidade global** (uma única linha para o Corolla placa ABC1D23, compartilhada entre todos os donos ao longo do tempo). Isso cria imediatamente um vetor de ataque: qualquer pessoa cadastra uma placa alheia e lê o histórico daquele veículo — que contém oficinas, cidades, valores gastos e padrões de uso do dono atual.

Isso é, simultaneamente, vazamento de dado pessoal (LGPD) e destruição da confiança do produto.

**Mitigação arquitetural (não negociável):**
- Adicionar um veículo é **claim**, não cadastro. O usuário reivindica um veículo.
- Enquanto o claim não for verificado, o usuário vê **apenas o que ele mesmo inseriu**. Nunca o histórico pré-existente.
- A API **nunca revela se um veículo já existe** na base (resposta idêntica para placa existente e inexistente).
- Verificação de claim por evidência: upload do CRLV / documento com chassi + nome, conferência assíncrona (automatizada quando possível, com fila de revisão manual no MVP).
- Rate limit agressivo por usuário/IP em qualquer rota que aceite placa ou chassi.
- Disputa de claim (dois usuários reivindicando o mesmo veículo) tem fluxo próprio, com bloqueio e revisão — **nunca merge silencioso**.

### RISCO 2 — Base legal do histórico persistente (crítico, jurídico)

Manter eventos após a venda do veículo é o coração do produto e o ponto mais delicado na LGPD. Dados do *veículo* (troca de óleo aos 40.000 km) não são dados pessoais; **mas ficam pessoais quando vinculáveis a um proprietário identificável**, e as notas fiscais anexadas contêm CPF, endereço e nome — inclusive de terceiros (a oficina, o mecânico).

**Mitigação arquitetural:**
- Separação física entre `vehicle_event` (fato técnico) e `event_actor` (quem registrou) — ver Documento B.
- Na transferência, o vínculo com o proprietário anterior é **pseudonimizado** ("Proprietário 1"), não excluído; o histórico técnico permanece.
- Documentos (PDF/foto de nota fiscal) **não acompanham** o veículo por padrão na transferência. O metadado extraído acompanha; o arquivo original fica com quem o enviou, salvo consentimento explícito.
- Registro de finalidade e base legal por categoria de dado, em tabela versionada (insumo do ROPA).
- **Recomendação:** revisão por advogado especializado em proteção de dados antes do lançamento público. Eu posso preparar o ROPA e o rascunho do DPIA; não substituo parecer jurídico.

### RISCO 3 — "Não inventar intervalos" vs. produto vazio (alto, de produto)

A §16 proíbe inventar recomendações técnicas. Correto — e é o que separa esse produto de dezenas de apps genéricos. Mas o efeito prático é que, sem uma base de intervalos oficiais, o motor de manutenção **não tem o que dizer** no dia 1. Manuais de fabricante são material protegido por direito autoral; não podem ser simplesmente copiados em massa.

**Mitigação:**
- Tabela `service_interval` com `source_type`, `source_citation`, `curated_by`, `verified_at` obrigatórios. Sem fonte, o registro não existe.
- No MVP: curadoria manual dos ~30 modelos mais vendidos no Brasil (Strada, Polo, Onix, HB20, Corolla, Compass, T-Cross, Argo, Mobi, Kwid, CG 160, Biz, Fan, XRE...) a partir de manuais públicos do proprietário, com citação da fonte e página. É trabalho de curadoria, não de engenharia — mas precisa ser orçado.
- Fallback honesto e visível na UI: *"Ainda não temos o plano oficial de manutenção deste modelo. Você pode informar o intervalo recomendado pelo seu manual."* — e esse dado do usuário vira `USER_REPORTED`, nunca `VERIFIED`.
- O usuário pode cadastrar seu próprio plano; isso alimenta a curadoria futura, sem virar verdade automática.

### RISCO 4 — Custo e alucinação da IA/OCR (médio-alto, operacional)

OCR de nota fiscal via modelo de visão custa por documento e erra. A §108 proíbe interface falsa; a §19 proíbe IA que inventa.

**Mitigação:**
- **Caminho preferencial de altíssima confiança, específico do Brasil:** ler o **QR Code / chave de acesso de 44 dígitos** do DANFE/NFC-e antes de tentar OCR. A chave é estruturada (UF, AAMM, CNPJ do emitente, modelo, série, número, código, DV) e permite validação determinística de emitente e data — sem IA. Só cai para OCR/visão quando não há chave legível.
- Pipeline em cascata: `barcode/QR → parser estruturado → OCR (visão) → revisão do usuário`. Cada etapa registra qual foi usada, e isso define o nível de confiança do dado.
- Todo dado extraído entra como `PENDING_CONFIRMATION`. Vira evento só depois do "confirmar" do usuário.
- Orçamento de IA por usuário/mês, cache por hash do documento, e circuit breaker global. Sem isso, um único usuário em loop gera fatura descontrolada.

### RISCO 5 — Servidor dedicado único (médio, operacional)

Servidor próprio reduz custo e é a escolha certa aqui. Mas é um único ponto de falha, e o dado é o ativo (§102).

**Mitigação:** backup off-site obrigatório desde o dia 1 (WAL archiving contínuo + objetos), com teste de restauração mensal documentado. Ver Documento D. **Backup não testado não é backup (§47).**

---

## 3. Stack escolhida e justificativa

Critérios de decisão, nesta ordem: (1) segurança e integridade auditáveis, (2) velocidade de uma equipe pequena, (3) uma só linguagem entre web, mobile e workers, (4) portabilidade do servidor dedicado para nuvem sem reescrita.

| Camada | Escolha | Por quê |
|---|---|---|
| Banco | **PostgreSQL 16** | Exigência do briefing e a escolha certa: RLS nativo, JSONB para payload de eventos, `pgcrypto`, particionamento declarativo, PITR maduro |
| Backend | **NestJS + Fastify (TypeScript)** | Módulos com fronteira explícita = mapeamento direto para o Domain Layer da §44; injeção de dependência torna `AIProvider`/`StorageProvider` (§85) triviais de trocar; tipos compartilhados com o front |
| Acesso a dados | **Drizzle ORM + SQL migrations versionadas** | Fica perto do SQL, o que importa quando se usa RLS, `SET LOCAL`, índices parciais e particionamento. ORMs muito abstratos atrapalham exatamente aqui |
| Frontend web | **Next.js (App Router) + Tailwind + shadcn/ui + TanStack Query** | O web é só um cliente (§78). BFF em route handlers para nunca expor token ao JS do browser |
| Fila | **BullMQ + Redis** | Simples, observável (bull-board), retry/backoff/DLQ prontos. Suficiente até milhões de jobs |
| Storage | **MinIO (API S3)** | Roda no servidor dedicado hoje; migrar para S3/R2 amanhã é mudar variável de ambiente, não código |
| Proxy/TLS | **Caddy** | TLS automático, config de 15 linhas, menos superfície de erro que Nginx manual |
| Auth | Implementada na aplicação: **Argon2id + refresh token rotativo em cookie httpOnly + TOTP** | Keycloak resolveria, mas adiciona um serviço crítico a operar. Com bibliotecas maduras e os testes do Documento C, o risco é aceitável e o controle é total |
| Observabilidade | **Pino (JSON) + OpenTelemetry + Prometheus/Grafana + Sentry** | Logs estruturados desde o commit 1 (§49) |
| Antivírus | **ClamAV** em worker isolado | §39 |
| Mobile (futuro) | **React Native / Expo** | Reaproveita o pacote `contracts` inteiro |

**Alternativas consideradas e descartadas:** Django (admin excelente e ORM maduro, mas o ecossistema de tipagem e o compartilhamento de contrato com o front são mais fracos para um produto API-first com mobile no roadmap); Go (melhor performance e menor consumo, mas custo de iteração alto para equipe pequena numa fase de descoberta de produto); Laravel (produtividade alta, porém menos natural para workers de longa duração e para contratos tipados de ponta a ponta).

**Decisão estrutural: monolito modular, não microsserviços.** A §44 descreve camadas, e camadas não exigem processos separados. Um monolito modular com fronteiras de módulo aplicadas por lint (`import/no-restricted-paths`) dá o mesmo isolamento lógico com uma fração do custo operacional — e extrair um módulo para serviço próprio depois é refatoração, não reescrita. São implantados **três processos** do mesmo código: `api`, `worker`, `scheduler`.

---

## 4. Componentes em execução

```
                          Internet (443)
                                │
                        ┌───────▼────────┐
                        │  Caddy (TLS)   │   rede: edge
                        └───┬────────┬───┘
                            │        │
                 ┌──────────▼──┐  ┌──▼──────────────┐
                 │ web (Next)  │  │ api (Nest)      │
                 │ BFF/SSR     │  │ REST /api/v1    │
                 └──────────┬──┘  └──┬───────┬──────┘
                            │        │       │
══════════════ rede interna (sem exposição pública) ══════════════
                            │        │       │
        ┌───────────┬───────┴────┬───┴───┬───┴─────────┐
        │           │            │       │             │
   ┌────▼─────┐ ┌───▼────┐ ┌─────▼───┐ ┌─▼──────┐ ┌────▼─────┐
   │PostgreSQL│ │ Redis  │ │  MinIO  │ │ClamAV  │ │ worker   │
   │  + WAL   │ │(fila)  │ │(objetos)│ │(scan)  │ │ scheduler│
   └────┬─────┘ └────────┘ └─────────┘ └────────┘ └────┬─────┘
        │                                              │
   ┌────▼──────────┐                          ┌────────▼────────┐
   │ backup off-   │                          │  AI Gateway     │
   │ site (S3/B2)  │                          │  (adapters)     │
   └───────────────┘                          └─────────────────┘
```

Filas do worker: `ocr`, `ai`, `alerts`, `maintenance-recalc`, `antivirus`, `notifications`, `exports`, `audit-anchor`.

---

## 5. Camadas dentro do backend

```
HTTP (controllers, DTOs, guards, rate limit)
   │  só traduz protocolo. Nenhuma regra aqui.
Application (use cases / commands)
   │  orquestra, abre transação, publica eventos de domínio
Domain (entidades, invariantes, políticas, value objects)
   │  ex.: OdometerConsistencyPolicy, ProvenanceLevel, VehicleClaim
Infrastructure (repositórios, storage, IA, e-mail, fila)
```

Regra de dependência: as setas apontam sempre para dentro. O Domain não importa nada de Infrastructure — o que torna testável, sem banco, exatamente a parte que não pode errar (regras de confiabilidade, consistência de KM, autorização).

---

## 6. Estrutura de diretórios

```
vehicle-life-os/
├── apps/
│   ├── api/                      # NestJS
│   │   └── src/
│   │       ├── modules/
│   │       │   ├── identity/     # usuários, sessões, MFA, consentimentos
│   │       │   ├── vehicles/     # veículo, identificadores, claim, transferência
│   │       │   ├── ownership/    # histórico de propriedade
│   │       │   ├── events/       # log de eventos + correções (núcleo)
│   │       │   ├── odometer/     # leituras + política de consistência
│   │       │   ├── documents/    # upload, storage, scan, OCR
│   │       │   ├── maintenance/  # motor de manutenção e planos
│   │       │   ├── knowledge/    # catálogo e intervalos oficiais
│   │       │   ├── alerts/
│   │       │   ├── sharing/      # links temporários, escopos, QR
│   │       │   ├── ai/           # Vehicle AI + guardrails + budget
│   │       │   ├── audit/
│   │       │   └── admin/
│   │       ├── shared/           # kernel de domínio, erros, provenance
│   │       └── infra/            # db, storage, queue, mail, telemetry
│   ├── worker/                   # mesmo código, processors BullMQ
│   └── web/                      # Next.js
├── packages/
│   ├── contracts/                # schemas Zod + tipos = fonte única da API
│   ├── domain/                   # regras puras compartilháveis
│   └── config/                   # eslint, tsconfig, tailwind
├── db/
│   ├── migrations/               # SQL versionado, um arquivo por mudança
│   └── seeds/                    # catálogo e intervalos curados (com fonte)
├── infra/
│   ├── docker/                   # Dockerfiles
│   ├── compose/                  # dev, prod
│   ├── caddy/
│   └── backup/                   # scripts pgBackRest / restic
├── docs/                         # estes documentos + ADRs
└── tests/
    ├── security/                 # IDOR, RLS, upload, rate limit
    └── e2e/
```

---

## 7. Decisões arquiteturais registradas (ADR resumido)

| # | Decisão | Consequência aceita |
|---|---|---|
| 001 | Event log append-only como fonte de verdade do histórico; projeções materializadas para leitura | Escrita mais complexa; leitura e auditoria triviais |
| 002 | Event sourcing **apenas** no domínio do veículo. Usuário, sessão e configuração são CRUD normal | Evita o custo de ES onde ele não paga |
| 003 | Identidade de veículo global e única, com claim verificado | Exige fluxo de verificação e resolução de disputa |
| 004 | Identificadores sensíveis (VIN, placa, CPF) cifrados na aplicação + índice cego HMAC para busca | Não dá para fazer `LIKE` em placa; busca é por igualdade exata (o que é suficiente) |
| 005 | RLS no PostgreSQL **somada** à autorização no serviço | Defesa em profundidade (§35): furo em uma camada não vaza dado |
| 006 | Proveniência é coluna obrigatória, não opcional | Nenhum fato entra no sistema sem origem — é impossível "esquecer" |
| 007 | Monolito modular, 3 processos | Simplicidade operacional hoje, extração possível amanhã |
| 008 | Soft delete + anonimização, nunca `DELETE` físico em histórico | Requer job de expurgo legal e política de retenção explícita |

---

## 8. O que eu recomendo cortar do MVP (e por quê)

Manter tudo no MVP é o modo mais confiável de nunca lançar. Recomendo adiar, **sem bloquear**:

- **Perfil de oficina / PROFESSIONAL_VERIFIED (§25-26).** O modelo de dados já prevê `PROFESSIONAL_REPORTED` e ator profissional. Mas oficina é outro produto, com outro onboarding e outra venda. Adiar para a fase 2 — e usar o MVP para descobrir quais oficinas os usuários já frequentam.
- **Diagnóstico orientativo (§20).** Maior risco de dano ao usuário e à marca, menor retorno inicial.
- **Score de histórico (§30).** Precisa de dados reais para ser calibrado; um score arbitrário no dia 1 é exatamente o "apresentar hipótese como fato" que a §19 proíbe. Registrar as métricas que o alimentarão; publicar só quando houver base.
- **Recall, TCO, comparação, frota, telemetria, marketplace.** Já são explicitamente futuro no briefing.
- **Transferência de veículo (§64).** Não está nos critérios de sucesso da §107. É o fluxo mais delicado juridicamente. Modelar agora, implementar na fase 2.

Fica no MVP tudo da §107 mais auditoria, backup e admin.

---

## 9. O que preciso de você antes da implementação

1. **Servidor:** vCPUs, RAM, disco (tipo e tamanho), provedor e localização. Isso muda decisões concretas (dá para rodar Postgres + MinIO + ClamAV + workers na mesma máquina? ClamAV sozinho quer ~2 GB).
2. **Domínio** registrado e quem controla o DNS.
3. **Orçamento mensal de IA/OCR** e destino de backup off-site (S3, Backblaze B2, outro servidor).
4. **Quem implementa** — eu escrevendo tudo em sessões sucessivas, você programando com meu apoio, ou uma equipe. Muda o formato da entrega, não a arquitetura.
5. **Curadoria dos manuais:** quem vai levantar os intervalos oficiais dos primeiros 30 modelos.

---

**Próximos documentos:** `02-MODELO-DE-DADOS.md` (B), `03-SEGURANCA-E-PRIVACIDADE.md` (E), `04-DEPLOY-E-OPERACAO.md` (F, J), `05-MVP-FLUXOS-E-API.md` (C, G, H, I).
