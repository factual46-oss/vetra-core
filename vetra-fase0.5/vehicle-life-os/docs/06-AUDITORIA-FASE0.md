# FASE 0 — SECURITY & ARCHITECTURE AUDIT

**Projeto:** VETRA / Vehicle Life OS
**Escopo:** todo o código da Fase 0 (46 arquivos)
**Data:** 16/08/2026 · **Revisão 2** (17/08/2026 — achados de auditoria externa independente)
**Veredito:** ⛔ **NOT APPROVED** — bloqueado exclusivamente pelo gate de execução (seção 9)

---

## 1. Resumo executivo

A auditoria interna encontrou **21 problemas**; uma **auditoria externa independente** encontrou mais **2**, ambos altos. Total: **23** — 1 crítico, 9 altos, 7 médios, 3 baixos, 3 informativos. Todos os críticos e altos estão corrigidos.

**Nota sobre a rodada externa (revisão 2).** Os dois achados externos merecem leitura atenta, porque dizem coisas diferentes sobre a auditoria interna:

- **AUD-22** (`identity.organization` sem RLS) é um caso em que **o mecanismo funcionou e o processo falhou**. A guarda `ops.tables_missing_rls()`, criada na própria rodada anterior, aponta exatamente essa tabela — foi projetada para isso. Ela nunca foi executada, porque o ambiente da auditoria não tinha PostgreSQL. É a prova concreta de que "corrigido mas não executado" não é o mesmo que "corrigido", e a razão pela qual o veredito segue NOT APPROVED.
- **AUD-23** (`SELECT` global em `audit.log`) é um erro de julgamento, não de execução. O `GRANT SELECT` tinha uma razão técnica real — o trigger de selo lê o hash anterior — e essa razão foi aceita sem perguntar se havia um caminho mais estreito. Havia: tornar o trigger `SECURITY DEFINER`. Uma necessidade legítima de 4 linhas dentro de um trigger virou privilégio de leitura sobre todo o histórico de auditoria.

O achado mais grave é do tipo que só apareceria em produção, no pior momento possível:

> **AUD-01 — o log auditável não funcionaria.** As extensões do PostgreSQL eram criadas no schema `public`, mas o script de inicialização executa `REVOKE ALL ON SCHEMA public FROM PUBLIC`. Como `vlos_app` nunca recebia `USAGE` em `public`, toda chamada a `digest()` — inclusive a do trigger que sela `audit.log` — falharia com *permission denied*. Na prática: **nenhuma ação auditável seria gravada**, e a descoberta viria na primeira tentativa de investigar um incidente.

Dois outros achados merecem destaque porque contrariam a intenção declarada da arquitetura:

- **AUD-08** — nada impedia a aplicação de conectar como `vlos_migrator`. A role dona das tabelas não é submetida às políticas de RLS. Uma variável de ambiente errada desligaria, em silêncio e sem nenhum erro visível, todo o isolamento entre usuários.
- **AUD-09** — `vlos_app` tinha `INSERT`/`UPDATE` em `identity.admin_permission`. Qualquer falha de autorização na camada de aplicação permitiria auto-elevação a administrador.

Além das correções, a Fase 0 ganhou o que faltava para o gate: o padrão de RLS aplicado às tabelas existentes, uma **guarda de regressão** que reprova no CI qualquer tabela nova sem RLS, os testes automatizados de isolamento entre usuários, a prova de detecção de adulteração da cadeia de auditoria, e a abstração de provedor de IA.

**Por que NOT APPROVED:** o ambiente onde a auditoria rodou não tem rede, Docker, PostgreSQL nem `npm install`. Não foi possível executar `npm test`, `typecheck`, `build` nem as migrations. O critério de aprovação (item 48 do gate) exige execução verde. As correções estão feitas e não há problema crítico ou alto **conhecido** em aberto — mas *não verificado* é diferente de *aprovado*, e essa distinção é justamente o que este gate existe para proteger. A seção 9 traz os seis comandos que fecham o gate.

---

## 2. Arquitetura atual

**Veredito: coerente.** Monolito modular com fronteiras explícitas, três processos do mesmo código-base (`api`, `worker`, `scheduler`). As camadas da §44 do briefing estão representadas por módulos, não por serviços separados — decisão correta para uma equipe pequena com servidor dedicado, e reversível (extrair um módulo é refatoração, não reescrita).

| Pergunta do gate | Resposta |
|---|---|
| Responsabilidades separadas? | Sim. `config`/`common`/`infra`/`modules`. Maior arquivo TS: 84 linhas. |
| Acoplamento desnecessário? | Um caso encontrado e corrigido (AUD-18). |
| Serviços que deveriam estar separados? | Não nesta fase. ClamAV e IA já são processos/adaptadores externos. |
| Arquivos monolíticos? | Não. Maior arquivo do projeto: `tools/migrate.mjs`, 135 linhas. |
| Dependências desnecessárias? | Não. `pino-http` é transitiva de `nestjs-pino` e pode sair do `package.json`. |
| Difícil de escalar? | Nada estrutural. Particionamento de eventos é decisão adiada conscientemente. |
| Dificulta Android/iOS? | Não. Nenhum estado de sessão no servidor, contratos em pacote compartilhado. Ver seção 2.1. |
| API-first real? | Sim, com uma ressalva registrada em AUD-21. |

**2.1 — Prontidão para mobile.** A API é a única interface; o web é cliente. O pacote `packages/contracts` (Zod) é consumível por React Native sem alteração. O ponto de atenção para a Fase 1: a autenticação por cookie `httpOnly` planejada para o web não serve a app nativo — o desenho precisa prever **os dois modos** (cookie para o web via BFF, Bearer para mobile e parceiros) desde o início, ou a Fase 1 terá que ser refeita quando o app chegar. Registrado como requisito obrigatório (seção 12).

---

## 3. Problemas encontrados

| ID | Problema | Severidade | Correção | Status |
|---|---|---|---|---|
| AUD-01 | Extensões em `public` + `REVOKE ALL ON SCHEMA public`: `digest()` inacessível a `vlos_app`. O trigger que sela `audit.log` falharia — **nenhuma auditoria gravada** | **CRÍTICO** | Schema `extensions` dedicado; chamadas sempre qualificadas; `GRANT USAGE`; passo de CI que escreve na auditoria *com a role da aplicação* | ✅ Corrigido |
| AUD-02 | Funções sem `search_path` fixado: sessão maliciosa poderia fazê-las resolver outro objeto | ALTO | `SET search_path = pg_catalog, public, extensions` em todas as funções | ✅ Corrigido |
| AUD-03 | Role `vlos_audit_w` documentada no `db/init` mas **nunca criada nem concedida** | MÉDIO | Removida. Decisão registrada: os grants de `vlos_app` (`INSERT`+`SELECT`) e as RULEs já isolam o log; uma terceira role exigiria segundo pool sem ganho | ✅ Corrigido |
| AUD-04 | Nenhuma tabela com RLS e nenhum mecanismo tornando-a obrigatória nas fases seguintes | ALTO | Migration `0006`: RLS em `identity.user` e `identity.admin_permission` + `ops.tables_missing_rls()` + `ops.rls_exemption` + verificação no CI | ✅ Corrigido |
| AUD-05 | `FORCE ROW LEVEL SECURITY` (recomendado no Doc 02) quebraria as funções `SECURITY DEFINER` de login e cadastro | INFORMATIVO (decisão) | Usar `ENABLE`. Suficiente porque a aplicação nunca é dona das tabelas. Risco residual coberto por AUD-08. Doc 02 reconciliado | ✅ Decidido |
| AUD-06 | `export const env = loadEnv()` no topo do módulo: qualquer import disparava validação. **Toda a suíte de testes falharia** em processo sem `DATABASE_URL` | ALTO | Resolução preguiçosa e memoizada (`getEnv()`) | ✅ Corrigido |
| AUD-07 | `trustProxy: true` incondicional: se a API for alcançável direto, qualquer cliente forja `X-Forwarded-For` e controla o IP visto pelo rate limit e pela auditoria | ALTO | `TRUSTED_PROXIES`; vazio = não confiar em nenhum | ✅ Corrigido |
| AUD-08 | Nada impedia `DATABASE_URL` apontar para `vlos_migrator` — a role dona não é submetida a RLS: **isolamento desligado em silêncio** | ALTO | Validação de ambiente recusa a inicialização; teste unitário cobre | ✅ Corrigido |
| AUD-09 | `vlos_app` com `INSERT`/`UPDATE` em `identity.admin_permission`: caminho de auto-elevação a admin | ALTO | `REVOKE`; concessão só por `identity.grant_admin_permission()` (`SECURITY DEFINER`), que exige motivo e grava na auditoria | ✅ Corrigido |
| AUD-10 | Dois geradores concorrentes de request-id (adapter e pino): o `traceId` devolvido ao cliente **não era** o do log | MÉDIO | Fonte única no Fastify, honrando o header quando vem de proxy confiável | ✅ Corrigido |
| AUD-11 | `withUserContext()` aceitava string arbitrária: valor inválido estouraria o cast da policy, virando erro 500 | MÉDIO | Validação de UUID antes de chegar ao banco | ✅ Corrigido |
| AUD-12 | `/health/ready` devolvia `err.message` — erros de conexão do Postgres carregam host, porta, usuário e motivo da recusa, em endpoint sem autenticação | ALTO | Detalhe só no log; cliente recebe `ok`/`error` | ✅ Corrigido |
| AUD-13 | Sem `statement_timeout`: consulta travada retém conexão do pool indefinidamente | MÉDIO | `statement_timeout: 15s` no pool | ✅ Corrigido |
| AUD-14 | `/health/ready` sem cache: endpoint público e gratuito disparava consulta ao banco por requisição | BAIXO | Cache de 3 s | ✅ Corrigido |
| AUD-15 | `bodyLimit` global de 1 MB — verificação do item 20 do gate | INFORMATIVO | Confirmado correto. Documentado que a rota de upload terá limite próprio e o global **não sobe** | ✅ Verificado |
| AUD-16 | Vitest não resolvia especificadores `.js` para fontes `.ts`: **nenhuma suíte carregaria** | ALTO | Alias de resolução em `vitest.config.ts` | ✅ Corrigido |
| AUD-17 | Regra de lint proibia qualquer import de `../../infra`, reprovando o `HealthController` — **CI vermelho por construção** | MÉDIO | Regra reescrita para a fronteira real (domínio não conhece infraestrutura), aplicada só onde ela existe | ✅ Corrigido |
| AUD-18 | `problem-details.ts` importava `@nestjs/common` só por um enum de status | BAIXO | Módulo desacoplado do framework; testado isoladamente | ✅ Corrigido |
| AUD-19 | `docker compose` sem `--env-file`: interpolação procuraria o `.env` ao lado do compose. As senhas que **criam** as roles ficariam diferentes das que a aplicação usa | MÉDIO | `--env-file .env` explícito em todos os scripts | ✅ Corrigido |
| AUD-20 | `.gitignore` sem `uploads/`, dumps, certificados e chaves | BAIXO | Ampliado | ✅ Corrigido |
| AUD-21 | Sem abstração de provedor de IA; sem `package-lock.json` (o Dockerfile usa `npm ci`) | INFORMATIVO | Porta `AIProvider` + `AIBudgetGuard` + `DisabledAIProvider` criadas. Lock gerado no primeiro `npm install` (documentado) | ✅ Corrigido |
| AUD-22 | `identity.organization` sem RLS e sem isenção — **a guarda criada na 0006 apontaria a tabela**, mas nunca foi executada. Expõe razão social, tipo, status de verificação e o vínculo pessoa↔empresa | **ALTO** (externo) | RLS habilitada; policy restringe leitura a membros; sem policy de escrita (onboarding será `SECURITY DEFINER` na Fase 2). Sem isenção — a guarda **não** foi silenciada | ✅ Corrigido |
| AUD-23 | `GRANT SELECT ON audit.log TO vlos_app`: a role operacional lia todo o histórico de auditoria, incluindo `actor_user_id`, `object_id`, `reason` e `metadata` de todos os usuários | **ALTO** (externo) | Trigger de selo vira `SECURITY DEFINER`; `REVOKE SELECT` em `audit.log` e `audit.chain_anchor`; `REVOKE EXECUTE` em `canonical_bytes`; RLS com policy apenas de `INSERT` | ✅ Corrigido |

---

## 4. Banco de dados

**Schemas.** Seis, com fronteira semântica clara: `identity`, `vehicle`, `knowledge`, `ops`, `ai`, `audit` — mais `extensions`, criado nesta auditoria. Separar em schemas (e não bancos) preserva integridade referencial e transação única.

**Roles — estado após a correção:**

| Role | Pode | Não pode |
|---|---|---|
| `vlos_migrator` | DDL, dona de tabelas e funções | não é usada pela aplicação (bloqueio na validação de ambiente) |
| `vlos_app` | `SELECT`/`INSERT`/`UPDATE` nas tabelas de domínio; `INSERT`/`SELECT` em `audit.log`; `EXECUTE` em `ops` e `extensions` | DDL, `DELETE`, `BYPASSRLS`, escrever em `admin_permission`, ler `audit.chain_anchor` |

Verificações do item 6 do gate, cobertas por teste automatizado: `vlos_app` não cria tabela, não faz `DROP`, não executa `DELETE`, não escreve privilégio administrativo.

**Constraints e integridade.** FKs presentes; índice único parcial de e-mail (`WHERE deleted_at IS NULL`) permite reuso após exclusão lógica — comportamento testado; trigger `updated_at`; catálogo de tipos de evento como *tabela* (não enum), de modo que adicionar tipo é `INSERT`, não migração; `payload_schema` por tipo, para que "genérico" não vire "sem estrutura".

**Soft delete.** `deleted_at` em `user` e `organization`; a role da aplicação não tem `DELETE` em lugar nenhum. Exceção legal (eliminação sob LGPD) roda por processo separado, fora da API — documentado, não implementado.

**Migrations.** Imutáveis por checksum, uma transação por arquivo, advisory lock contra deploy concorrente. O CI valida o ciclo *banco vazio → migrations → banco funcional* e a idempotência da segunda execução.

**Nota de honestidade sobre imutabilidade de migrations.** Esta auditoria **editou** as migrations `0001`, `0002`, `0004` e `0005`, o que a regra do projeto proíbe. A justificativa: nenhuma delas jamais foi aplicada a nenhum banco — não existe instalação para migrar. Corrigir `0001` é preferível a carregar para sempre uma migração que cria extensões no lugar errado e uma segunda que as move. **Este é o último momento em que isso é permitido.** A partir da primeira aplicação em qualquer ambiente, correção é arquivo novo.

---

## 5. Segurança

**Isolamento (itens 7, 8 e 9 do gate).** Três camadas independentes, na ordem em que atuam: guard de rota → política de domínio → RLS no PostgreSQL. A terceira é a que esta fase entregou, e é a que continua valendo quando as duas primeiras falham. O teste `tests/security/isolation.spec.ts` ataca exatamente essa camada, conectado como `vlos_app`:

- A enxerga apenas o próprio registro;
- A não lê B **mesmo informando o id exato** (o caso IDOR/BOLA);
- B não lê A (teste inverso);
- sem `app.user_id`, zero linhas — falha fechado;
- A não altera B;
- a role não tem `DELETE`, não executa DDL, não escreve privilégio administrativo.

Na Fase 2, quando `vehicle.vehicle` existir, os mesmos casos são replicados para veículo, evento e documento. A estrutura do arquivo já prevê isso.

**IDOR/BOLA.** UUIDv4 (não sequencial); resposta **404, nunca 403**, para recurso existente sem permissão — 403 confirma a existência do recurso, e no caso de placas e chassis isso já é vazamento. Regra registrada no módulo de erros.

**Segredos.** `.env` e derivados ignorados pelo Git; `.env.example` sem valor real; `gitleaks` no CI; redação obrigatória no logger, incluindo `connectionString`. Nenhum segredo encontrado no código, no README ou no histórico de arquivos.

**Rate limiting.** Especificado com limites por rota no Doc 03, **não implementado** — é Fase 1. Preferi não deixar um middleware meio pronto e não testado do que parecer mais avançado do que está.

**Superfície HTTP.** `bodyLimit` global de 1 MB mantido deliberadamente. CSP, HSTS, `frame-ancestors 'none'`, `nosniff`. CORS obrigatório em produção (vazio bloquearia o cliente web — e a validação avisa em vez de deixar descobrir em produção).

---

## 6. Auditoria

O log é selado por **trigger no banco**, não pela aplicação. Consequência: não existe caminho de código capaz de gravar entrada não selada, e existe uma única implementação da canonicalização — a mesma usada pela verificação. `UPDATE` e `DELETE` anulados por RULE, inclusive para a dona da tabela.

Provado por teste (`tests/security/audit-chain.spec.ts`):

1. cada entrada encadeia ao hash da anterior;
2. `verify_chain()` não aponta quebra em operação normal;
3. `UPDATE`/`DELETE` são anulados;
4. **adulteração com privilégio de dono é detectada** — o teste desativa a RULE, altera uma linha, confirma que `verify_chain()` aponta o `id` exato, e restaura.

**Limitação (item 11 do gate), documentada no README e na própria tabela:** hash chain prova *consistência interna*, não imutabilidade física. Quem controla o banco pode reescrever a cadeia inteira e recalcular todos os hashes. A prova real vem de ancorar periodicamente `(último id, último hash)` em storage externo append-only/WORM, fora do alcance do administrador do servidor. A tabela `audit.chain_anchor` existe para receber essas âncoras; o job de exportação é requisito da Fase 9. Não construí infraestrutura WORM agora — seria complexidade sem uso.

**Privilégios sobre o log (AUD-23).** A aplicação insere e nada mais:

| Operação | `vlos_app` | Como é garantido |
|---|---|---|
| `INSERT` | ✅ | `GRANT INSERT` + policy `audit_log_append_only` |
| `SELECT` | ❌ | `REVOKE SELECT` + ausência de policy de leitura |
| `INSERT ... RETURNING` | ❌ | `RETURNING` exige `SELECT` — bloqueio deliberado |
| `UPDATE` / `DELETE` | ❌ | privilégio revogado + RULEs |
| `canonical_bytes()` | ❌ | `REVOKE EXECUTE` — impede calcular hashes válidos offline |

O trigger `audit.seal_entry()` passou a `SECURITY DEFINER`: lê o hash anterior com o privilégio da dona, num caminho de quatro linhas que não aceita parâmetro do chamador. É o que permite tirar o `SELECT` da aplicação sem quebrar o encadeamento.

Não existe caminho de leitura implementado, e isso é deliberado — sem área de conta e sem painel administrativo, uma role de leitura seria privilégio ocioso. Os dois caminhos legítimos estão registrados como requisito: `audit.list_own_entries()` (`SECURITY DEFINER`, escopo do titular, Fase 1) e a role `vlos_audit_reader` com pool próprio para o console administrativo (Fase 9).

**Auditoria administrativa (item 12).** `identity.grant_admin_permission()` exige motivo com no mínimo 10 caracteres, verifica se quem concede possui `admin:grant`, e grava a concessão no log auditável. Administrador não tem acesso por ser administrador: tem as permissões nominais que alguém concedeu, com motivo registrado.

---

## 7. Privacidade

A separação exigida pelo item 13 está no modelo desde o desenho: `vehicle` (fato técnico) não referencia proprietário; o vínculo vive em `ownership`, com `anonymized_at` para pseudonimização na transferência. Identificadores sensíveis (VIN, placa, RENAVAM) ficam em tabela própria, cifrados com AES-GCM e com índice cego HMAC — um dump sem a KEK e sem o pepper não revela nem permite testar placas.

Nesta fase, o que existe de concreto é a validação que **impede subir em produção com KEK igual ao pepper** ou com chaves ausentes, e a redação obrigatória nos logs. As tabelas de veículo chegam na Fase 2.

**Organizações (AUD-22).** A entidade cobre oficina, concessionária, frota e seguradora. A tentação é tratá-la como dado público — "nome de oficina é público" — o que confunde o diretório curado de oficinas *verificadas* (produto futuro) com a tabela operacional, onde também vivem cadastros em análise e frotas privadas, para quem a própria existência do registro é informação de negócio. Decisão: protegida por padrão, visível apenas a membros. Visibilidade pública será opt-in explícito com policy própria. Restrição é relaxável depois; vazamento não é.

Sobre proveniência (item 15): a nomenclatura foi conferida e está consistente entre o enum do banco, o pacote de contratos e os documentos — `VERIFIED`, `PROFESSIONAL_REPORTED`, `USER_REPORTED`, `EXTERNAL_SOURCE`, `SYSTEM_INFERRED`, `UNVERIFIED`. Os campos de origem (`source_type`, `source_ref`, `confidence`, `verified_at`, `verified_by`) são `NOT NULL` no desenho da tabela de eventos.

---

## 8. IA

Nenhuma chamada de IA existe nesta fase — o que está entregue é a porta e as travas.

| Exigência do gate | Estado |
|---|---|
| Um provedor por vez (31) | `AI_PROVIDER` é enum de valor único; padrão `none` |
| Abstração trocável (31) | `AIProvider` + `AI_PROVIDER` token de injeção |
| Controle de custo (32) | `AIBudgetGuard` separado do provedor — trocar de fornecedor não perde o controle de custo junto |
| Orçamento obrigatório (32) | Habilitar provedor sem `AI_API_KEY`, orçamento diário ou limite por usuário **impede a aplicação de subir** |
| Determinístico não vai para IA (33) | `DETERMINISTIC_INTENTS` cataloga as perguntas que são SQL |
| RAG, nunca o banco inteiro (34) | `AICompletionRequest.context` recebe fatos recuperados, cada um com proveniência |
| Minimização de contexto (35) | O tipo não admite "dump"; só lista de fatos |
| Prompt injection (35) | `RetrievedFact.untrusted` marca conteúdo vindo de documento do usuário, que o adaptador delimita como dado |
| Sem alucinação (36) | `INSUFFICIENT_DATA_ANSWER` constante; `DisabledAIProvider` **lança erro** em vez de devolver texto plausível |

A decisão que vale registrar: quando não há provedor, o sistema falha alto e claro. Uma resposta fabricada sobre manutenção de veículo é pior que erro nenhum.

---

## 9. Testes executados

**Ambiente desta auditoria: sem rede, sem Docker, sem PostgreSQL, sem `npm install`.** O que segue distingue o que rodou de fato do que não pôde rodar. Nada foi marcado como aprovado sem execução.

| Teste | Resultado | Observação |
|---|---|---|
| Estrutura das migrations (parênteses, delimitadores, `digest()` sempre qualificado) | **PASS** | Executado |
| Seed: 25 tipos de evento, sem código duplicado | **PASS** | Executado |
| Sintaxe do runner de migrations (`node --check`) | **PASS** | Executado |
| Typecheck estrito dos módulos sem dependência externa | **PASS** | Executado (`problem-details`, `ai-provider`, `queues`) |
| Testes de comportamento executados de fato (6 asserções) | **PASS** | Provedor de IA desativado lança erro; resposta padrão de ausência de dados; intenção determinística catalogada; erro 5xx não vaza detalhe interno; erro 4xx preserva detalhe; título traduzido |
| Typecheck completo (`npm run typecheck`) | **NÃO EXECUTADO** | Exige `npm install`. Os 47 erros restantes na verificação parcial são todos `TS2307`/`@types/node` ausentes — nenhum erro de lógica de tipo detectável offline |
| `npm test` (Vitest) | **NÃO EXECUTADO** | Vitest não instalado |
| `npm run build` | **NÃO EXECUTADO** | Dependências ausentes |
| `npm run lint` | **NÃO EXECUTADO** | ESLint não instalado |
| Migrations contra PostgreSQL | **NÃO EXECUTADO** | Sem PostgreSQL nem Docker |
| Integridade da cadeia de auditoria | **NÃO EXECUTADO** | Teste escrito; exige banco |
| Isolamento entre usuários (A ↛ B) | **NÃO EXECUTADO** | Teste escrito; exige banco |
| Isolamento de organizações (AUD-22) | **NÃO EXECUTADO** | 5 casos escritos; exige banco |
| Privilégios sobre `audit.log` (AUD-23) | **NÃO EXECUTADO** | 8 casos escritos; exige banco |
| `ops.tables_missing_rls()` = 0 | **NÃO EXECUTADO** | **Teria apontado AUD-22.** Exige banco |
| Docker build / compose | **NÃO EXECUTADO** | Docker indisponível |

**Os seis comandos que fecham o gate** (10 a 15 minutos na sua máquina):

```bash
npm install                        # gera o package-lock.json
npm run lint && npm run typecheck && npm run build
npm run dev:infra && npm run db:migrate && npm run db:seed
npm test
export TEST_DATABASE_URL_APP=postgres://vlos_app:<senha>@localhost:5432/vlos
export TEST_DATABASE_URL_MIGRATOR=postgres://vlos_migrator:<senha>@localhost:5432/vlos
npm run test:db
```

Com esses comandos verdes — e o CI verde no primeiro push — a Fase 0 passa a **APPROVED**. Me mande a saída se algo quebrar: como não pude executar, é razoável esperar ajuste em versão de dependência ou detalhe de sintaxe SQL.

---

## 10. Riscos restantes

| Risco | Severidade | Mitigação atual | Quando resolve |
|---|---|---|---|
| Correções não verificadas por execução | **ALTO** | Testes escritos e CI configurado | Gate da seção 9 |
| Hash chain reescrevível por quem controla o banco | MÉDIO | Documentado; `audit.chain_anchor` pronta | Fase 9 (export WORM) |
| Sem autenticação, autorização de rota e rate limiting | ALTO (aceito) | É o objeto da Fase 1 | Fase 1 |
| Aplicação poderia conectar como role dona | Baixo (mitigado) | Validação de ambiente + teste | Resolvido |
| Servidor dedicado é ponto único de falha | MÉDIO | Backup off-site append-only documentado | Fase 10 |
| Base de intervalos oficiais inexistente | MÉDIO | `source_citation NOT NULL` impede inventar | Curadoria (fora de engenharia) |
| Autenticação por cookie não serve app nativo | MÉDIO | Identificado agora, antes de implementar | Requisito da Fase 1 |

---

## 11. Débitos técnicos

1. `pino-http` declarado como dependência direta sendo transitiva de `nestjs-pino`.
2. `apps/api/tsconfig.json` exclui `*.spec.ts` do typecheck — specs não são verificados por tipo no build.
3. `docker-compose.prod.yml` ainda não existe (previsto para a Fase 10); só o de desenvolvimento.
4. Nenhum teste de contrato HTTP — não há rota autenticada ainda para testar.
5. Healthcheck do MinIO usa `mc ready local`, não validado contra a imagem.
6. Sem `package-lock.json` até o primeiro `npm install`; o `Dockerfile` usa `npm ci` e depende dele.
7. Verificação da cadeia de auditoria ainda não roda em job agendado (Fase 9).
8. Sem caminho de leitura da auditoria — nem para o titular (LGPD) nem para o console administrativo. Requisito das Fases 1 e 9, com desenho já definido.
9. `identity.organization` não tem tabela de papéis de membro; a policy usa `user.organization_id` diretamente. Suficiente hoje; vira `organization_member` quando oficinas tiverem mais de um perfil (Fase 2).

---

## 12. Requisitos obrigatórios da Fase 1

Levantados por esta auditoria. São condições de entrada, não sugestões:

1. **`identity.register_user()` e `identity.authenticate_lookup()` como `SECURITY DEFINER`.** Com RLS ativa, cadastro e login precisam de um caminho estreito e auditado para operar antes de existir contexto de usuário. Sem isso, a Fase 1 vai descobrir que não consegue nem buscar o usuário pelo e-mail.
2. **Autenticação em dois modos desde o início:** cookie `httpOnly` para o web (via BFF) e Bearer para mobile e parceiros. Decidir isso depois significa refazer a Fase 1.
3. **Resposta 404, nunca 403,** para recurso existente sem permissão.
4. **Rate limiting** em login, recuperação de senha e API geral, com contadores no Redis.
5. **Ampliar `tests/security/isolation.spec.ts`** para a camada HTTP: token ausente, token inválido, token expirado, id inexistente, id de outro usuário, usuário comum em rota administrativa.
6. **Toda nova tabela com dado de usuário nasce com RLS.** O CI já reprova o contrário; não desative a verificação — registre isenção justificada em `ops.rls_exemption` se for realmente uma tabela de referência.
7. **`audit.list_own_entries()` como `SECURITY DEFINER`**, escopo fechado no titular, para atender ao direito de acesso da LGPD sem devolver `SELECT` à role da aplicação.
8. **Detecção de reuso de refresh token** com revogação de toda a família — é o que transforma roubo de token de comprometimento silencioso em incidente detectado.

---

## 13. Veredito

# ⛔ NOT APPROVED

**O que falta, e só isto:** executar os seis comandos da seção 9 em ambiente com rede, Docker e PostgreSQL, e confirmar que passam.

A rodada externa reforçou o ponto em vez de enfraquecê-lo: um dos dois achados era detectável por uma verificação automatizada que já existia no repositório e que nunca rodou. Enquanto a suíte não for executada de fato, a lista de "problemas conhecidos" mede o que foi lido, não o que funciona.

Não há problema **crítico** ou **alto** conhecido em aberto. Os 23 achados foram tratados: 20 corrigidos, 2 verificados como corretos, 1 decidido e documentado. O que impede a aprovação não é uma pendência de código — é que a auditoria não pôde executar o próprio critério de aprovação, e declarar aprovado sem isso seria exatamente o tipo de atalho que este gate existe para impedir.
