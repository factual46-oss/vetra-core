# VETRA — Vehicle Life OS

> "O veículo muda de dono. A história continua."

## Objetivo

Infraestrutura de identidade, histórico e inteligência do ciclo de vida de veículos.
O produto não é o aplicativo: é um **log de eventos com proveniência auditável,
ancorado numa identidade de veículo estável**. Timeline, passaporte digital,
relatório de venda e IA são projeções de leitura sobre esse log.

**Estado: Fase 0 (Fundação) — auditada.** Ver `docs/06-AUDITORIA-FASE0.md`
para o resultado do gate, os defeitos corrigidos e o que ainda falta validar.

---

## Arquitetura

Monolito modular, três processos do mesmo código-base:

```
Internet → Caddy (TLS) → api (Nest/Fastify) ─┬→ PostgreSQL 16   (dado + RLS + auditoria)
                       → web (cliente)       ├→ Redis           (fila e rate limit)
                                             ├→ MinIO (S3)      (documentos, bucket privado)
                       worker / scheduler ───┴→ ClamAV / IA     (processamento assíncrono)
```

Rede interna sem rota para a internet: só o Caddy publica porta.
Camadas dentro da API: `HTTP → Application → Domain → Infrastructure`, com as
dependências sempre apontando para dentro.

Decisões completas e alternativas descartadas em `docs/01-ARQUITETURA.md`.

## Stack

| Camada | Escolha |
|---|---|
| Banco | PostgreSQL 16 (RLS, JSONB, pgcrypto, PITR) |
| Backend | NestJS + Fastify (TypeScript) |
| Migrations | SQL puro versionado + runner próprio (`tools/migrate.mjs`) |
| Fila | BullMQ + Redis |
| Storage | MinIO (API S3) → portável para S3/R2 |
| Proxy | Caddy (TLS automático) |
| Observabilidade | Pino (JSON, com redação) + health checks |
| Testes | Vitest, incluindo suíte contra PostgreSQL real |

## Estrutura

```
apps/api            API REST. Módulo = fronteira de domínio.
apps/worker         Processadores de fila.
packages/contracts  Schemas Zod — fonte única dos contratos da API.
db/migrations       SQL versionado e imutável.
db/seeds            Catálogo (idempotente).
db/init             Criação de roles (roda uma vez, na primeira subida do Postgres).
tools/migrate.mjs   Runner de migrations com checksum e advisory lock.
tests/security      Isolamento entre usuários e integridade da auditoria.
tests/db            Constraints, transações, migrations.
docs/               Arquitetura, modelo de dados, segurança, deploy, MVP, auditoria.
```

---

## Instalação

Pré-requisitos: Node.js 22+, Docker e Docker Compose, `psql` (opcional).

```bash
git clone <repo> vetra && cd vetra
cp .env.example .env

# Gere as três chaves — KEK e pepper NÃO podem ser iguais
echo "APP_KEK_BASE64=$(openssl rand -base64 32)"
echo "IDENTIFIER_PEPPER_BASE64=$(openssl rand -base64 32)"
echo "AUDIT_IP_HASH_KEY_BASE64=$(openssl rand -base64 32)"
# copie para o .env, junto com senhas próprias para POSTGRES/APP/MIGRATOR/REDIS

npm install          # gera o package-lock.json exigido pelo Dockerfile
npm run dev:infra    # sobe postgres, redis e minio
npm run db:migrate
npm run db:seed
npm run dev          # sobe também api e worker
```

Verificação:

```bash
curl -s localhost:3000/health/live    # {"status":"ok"}
curl -s localhost:3000/health/ready   # checks de postgres e redis
npm run db:status                     # migrations aplicadas
```

## Testes

```bash
npm run lint
npm run typecheck
npm run build
npm test                              # unitários (não precisam de banco)

# Suíte de segurança e banco — exige PostgreSQL migrado
export TEST_DATABASE_URL_APP=postgres://vlos_app:<senha>@localhost:5432/vlos
export TEST_DATABASE_URL_MIGRATOR=postgres://vlos_migrator:<senha>@localhost:5432/vlos
npm run test:db
```

Sem as variáveis, as suítes de banco aparecem como **skipped** — nunca como
passed. Teste de segurança que passa sem rodar é pior que teste nenhum.

## Banco de dados

**Três papéis, privilégio mínimo:**

| Role | Pode | Não pode |
|---|---|---|
| `vlos_migrator` | DDL, dona das tabelas, roda migrations | não é usada pela aplicação |
| `vlos_app` | SELECT/INSERT/UPDATE nas tabelas de domínio; **apenas INSERT** em `audit.log` | DDL, DELETE, BYPASSRLS, escrever em `identity.admin_permission`, **ler `audit.log`** |
| `postgres` | superusuário | usado só na criação inicial |

A API recusa iniciar se `DATABASE_URL` apontar para `vlos_migrator` — a role dona
não é submetida às políticas de RLS, e conectar com ela desligaria em silêncio
todo o isolamento entre usuários.

**Migrations** são imutáveis: o runner compara checksum e falha se um arquivo já
aplicado mudou. Correção é arquivo novo. Banco vazio + `db:migrate` + `db:seed`
produz um banco funcional sem nenhum passo manual (verificado no CI).

## Segurança

- **Isolamento por RLS**, aplicada no PostgreSQL com a role da aplicação. Sem
  `app.user_id` definido na transação, zero linhas: falha fechado.
- **`ops.tables_missing_rls()`** aponta qualquer tabela nova sem RLS; o CI falha
  se retornar alguma. Isenção só com justificativa registrada em
  `ops.rls_exemption`.
- **Log auditável** encadeado por hash, selado por trigger no banco. `UPDATE` e
  `DELETE` anulados por RULE, inclusive para a dona da tabela.
- **Auditoria é write-only para a aplicação.** `vlos_app` insere e nada mais —
  sem `SELECT`, sem `INSERT ... RETURNING`, sem executar a função de
  canonicalização. O trigger de selo é `SECURITY DEFINER`, então não precisa que
  a aplicação enxergue a tabela para encadear o hash.
- **`identity.organization` é protegida por padrão**: visível apenas a membros.
  Diretório público de oficinas verificadas, quando existir, será opt-in com
  policy própria — restrição é relaxável depois, vazamento não é.
- **Privilégio administrativo** só é concedido por
  `identity.grant_admin_permission()`, que exige motivo e grava na auditoria.
- **Redação de logs** por configuração: senha, token, CPF, VIN, placa, RENAVAM e
  cabeçalhos de autorização nunca chegam ao disco em claro.
- **Sem confiança cega em proxy**: `TRUSTED_PROXIES` vazio = não confiar em
  nenhum `X-Forwarded-For`.
- **Body limit global de 1 MB.** Upload terá rota, limite e validações próprios —
  o limite global não sobe para acomodar arquivo grande.

Modelo de ameaça e controles completos em `docs/03-SEGURANCA-E-PRIVACIDADE.md`.

## Variáveis de ambiente

Todas descritas em `.env.example`. A aplicação **não sobe** com configuração
inválida — validação por schema na inicialização, com regras extras em produção
(chaves obrigatórias, CORS definido, KEK ≠ pepper, IA com orçamento).

Nenhum segredo no repositório: `.env` está no `.gitignore` e o CI roda `gitleaks`.

## Backup e restore

Estratégia completa em `docs/04-DEPLOY-E-OPERACAO.md`. Resumo:

| Item | Política |
|---|---|
| Banco | pgBackRest: full semanal, incremental diário, WAL contínuo |
| Documentos | restic diário para destino externo |
| Off-site | provedor diferente do servidor, credenciais **append-only** |
| Cifragem | chave fora do servidor |
| Teste de restauração | mensal, cronometrado, registrado |
| Metas | RPO 5 min · RTO 2 h |

**Backup nunca restaurado não é backup.** O primeiro teste de restauração é
executado antes de qualquer dado real entrar no sistema.

## Limitações conhecidas

1. **Hash chain não é imutabilidade física.** Quem controla o banco pode
   reescrever a cadeia inteira. A prova real exige ancorar periodicamente
   `(último id, último hash)` em storage externo append-only/WORM. A tabela
   `audit.chain_anchor` existe; o job de exportação é requisito da Fase 9.
2. **Sem autenticação ainda.** Não há login, sessão, MFA nem rate limiting
   implementados — é a Fase 1. O padrão de RLS já está no banco e os testes de
   isolamento já rodam.
3. **RLS usa `ENABLE`, não `FORCE`.** Suficiente porque a aplicação nunca é dona
   das tabelas; `FORCE` quebraria as funções `SECURITY DEFINER` que o login e o
   cadastro exigirão. O risco residual (aplicação conectar como dona) é
   bloqueado na validação de ambiente.
4. **Sem tabelas de veículo.** `vehicle.event_type` é só o catálogo. As tabelas
   de veículo, evento e documento chegam nas Fases 2 a 4.
5. **Rate limiting apenas especificado**, não implementado (Fase 1).
6. **Não há caminho de leitura da auditoria.** Deliberado: sem área de conta e
   sem painel admin, uma role ou função de leitura seria privilégio ocioso. O
   acesso do titular (LGPD) vira `audit.list_own_entries()` na Fase 1; o console
   administrativo ganha a role `vlos_audit_reader` na Fase 9.

## Próximos passos — Fase 1 (Identidade)

Requisitos obrigatórios levantados pela auditoria:

- `identity.register_user()` e `identity.authenticate_lookup()` como
  `SECURITY DEFINER` — únicas portas para criar conta e buscar por e-mail antes
  de existir contexto de usuário.
- Argon2id, refresh token rotativo com detecção de reuso, TOTP.
- Rate limiting em login, recuperação de senha e API geral.
- Guard de autorização + política de domínio, com resposta **404 (não 403)**
  para recurso existente sem permissão.
- Ampliar `tests/security/isolation.spec.ts` para as rotas HTTP.

## Regras do repositório

1. Migrations são imutáveis. Correção é arquivo novo.
2. Nada de `DELETE` em histórico — a role da aplicação não tem a permissão.
3. Toda consulta a dado de usuário passa por `withUserContext()`.
4. Nenhum fato entra sem proveniência.
5. Nenhum segredo no Git.
6. Nada de dado fictício, botão inerte ou erro escondido.
