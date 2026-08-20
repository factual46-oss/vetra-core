# VETRA — FASE 1A IMPLEMENTATION REPORT

**Data:** 19/08/2026
**Escopo:** Fase 1A (núcleo de autenticação), conforme plano revisado homologado

---

## 1. Implementado

| Item | Estado |
|---|---|
| Registro de usuário | ✅ com resposta anti-enumeração (202 sempre) |
| Login e-mail + senha | ✅ erro único e indistinguível para todas as falhas |
| Argon2id com pepper | ✅ `@node-rs/argon2`, HMAC-SHA256 antes do hash, re-hash automático |
| Normalização de e-mail | ✅ política única (NFKC + trim + minúsculas), documentada e testada |
| Sessões | ✅ criação, expiração, revogação, listagem própria, IP/UA só em HMAC |
| Access token EdDSA | ✅ claims mínimas, `kid`, conjunto com `active`/`next`/`retiring` |
| Refresh com rotação | ✅ consumo atômico por `UPDATE` condicional |
| Detecção de replay | ✅ revoga a família inteira, encerra a sessão, audita |
| Logout e logout-all | ✅ revoga sessão e tokens |
| Rate limiting | ✅ dois eixos, política de falha por endpoint |
| Revogação com janela zero | ✅ verificação de sessão a cada requisição, sob RLS |
| CSRF | ✅ double-submit apenas no modo cookie |
| Auditoria | ✅ 15 ações, sanitização de metadata, sem infraestrutura nova |
| Integração com RLS | ✅ `sub` → `withUserContext` → `app.user_id`, sem segundo identificador |

**Fora do escopo, conforme item 37/38:** recuperação de senha, verificação de e-mail e TOTP são **Fase 1B**. Nada de veículos, oficinas, OCR ou IA.

---

## 2. Arquivos criados

**Migrations (3)**
`db/migrations/0008_identity_auth.sql` · `0009_identity_functions.sql` · `0010_auth_hardening.sql`

**Domínio (4)** — puro, sem dependência externa
`auth/domain/email.ts` · `password-policy.ts` · `opaque-token.ts` · `jwt-keyset.ts`

**Infraestrutura (8)**
`auth/infra/auth-database.service.ts` · `password-hasher.service.ts` · `jwt.service.ts` · `rate-limit.service.ts` · `auth-audit.service.ts` · `session.repository.ts` · `refresh-token.repository.ts` · `credential.repository.ts`

**Aplicação, HTTP e módulo (7)**
`auth/application/auth.service.ts` · `refresh.service.ts` · `auth.controller.ts` · `auth.module.ts` · `guards/auth.guard.ts` · `guards/csrf.guard.ts` · `dto/auth.schemas.ts` + `dto/zod-validation.pipe.ts`

**Testes (9 suítes)**
`tests/auth/domain.spec.ts` · `jwt.spec.ts` · `registration-login.spec.ts` · `refresh.spec.ts` · `session-logout.spec.ts` · `rate-limit.spec.ts` · `tests/security/auth-privileges.spec.ts` · `authorization-confusion.spec.ts` · `connection-reuse.spec.ts`
Mais `tests/setup-env.ts` e `tests/helpers/auth.ts`.

**Ferramentas (3)**
`tools/gen-jwt-key.mjs` · `tools/bench-argon2.mjs` · `tools/check-test-results.mjs`

---

## 3. Arquivos modificados

| Arquivo | Mudança |
|---|---|
| `apps/api/src/config/env.ts` | Variáveis da Fase 1A + validação de segregação de roles |
| `apps/api/src/app.module.ts` | Registro do `AuthModule` |
| `apps/api/src/main.ts` | Plugin `@fastify/cookie` |
| `apps/api/package.json` | `@node-rs/argon2`, `jose`, `@fastify/cookie@^9`; **helmet mantido em `^11.1.1`** |
| `db/init/01-roles.sh` | Criação de `vlos_auth` |
| `.env.example`, `docker-compose.dev.yml` | Variáveis e credencial do pool de auth |
| `.github/workflows/ci.yml` | Serviço Redis, role `vlos_auth`, novas variáveis, verificação de skip |
| `eslint.config.js` | Proíbe `queryUnscoped`/`transactionUnscoped` fora de `infra/` |
| `vitest.config.ts` | `setupFiles` e timeouts maiores (Argon2) |
| **`apps/api/src/config/env.spec.ts`** | **Ver seção 11 — única alteração em teste existente, declarada** |

**Sincronização:** reapliquei as quatro correções do CI round 2 que estavam apenas no GitHub (`@fastify/helmet@^11.1.1`, contrato estrutural em `request-id.ts`, `import { Redis }` em dois arquivos, união `Http2ServerRequest` no `genReqId`). O pacote não regride nenhuma delas.

---

## 4. Migrations

**`0008_identity_auth.sql`** — `identity.credential`, `identity.session`, `identity.refresh_token`, com RLS, policies e grants mínimos.

O ponto crítico desta migration: a `0005` tem `ALTER DEFAULT PRIVILEGES` que concede `SELECT/INSERT/UPDATE` a `vlos_app` em **toda tabela nova** do schema `identity`. Sem os `REVOKE` explícitos, `identity.credential` nasceria legível pela role da aplicação e a Alternativa B estaria furada no dia zero, em silêncio.

**`0009_identity_functions.sql`** — `register_user`, `authenticate_lookup`, `set_password`. Owner `vlos_migrator`, `search_path` fixo, `REVOKE ALL FROM PUBLIC`, `EXECUTE` apenas para `vlos_auth`.

**`0010_auth_hardening.sql`** — não cria nada: verifica por **lista branca** (23 privilégios declarados) e falha o deploy se qualquer role de aplicação tiver privilégio não declarado. Também confere ausência de `BYPASSRLS`, ausência de posse de tabela, `EXECUTE` das funções de credencial e `ops.tables_missing_rls() = 0`.

Nenhuma migration cria role com senha — isso colocaria segredo em arquivo versionado (item 23). `vlos_auth` nasce no bootstrap; a `0008` falha com mensagem explícita se a role não existir.

---

## 5. Segurança

**Argon2id.** `m=19456 KiB, t=3, p=1` (mínimo OWASP), configuráveis e gravados **por linha** em `credential`. Pepper aplicado por HMAC-SHA256 antes do hash — escolhido em vez da opção `secret` da biblioteca porque é testável sem o módulo nativo e sobrevive a uma troca de biblioteca sem invalidar senhas. O HMAC também limita a entrada do Argon2 a 32 bytes, neutralizando DoS por senha gigante.

**Access token.** EdDSA, 10 min, claims `sub`/`sid`/`jti`/`amr`/`iss`/`aud`. Sem e-mail, sem nome, sem papel. `algorithms: ['EdDSA']` explícito na verificação — sem essa whitelist, um token com `alg: HS256` usando a chave pública como segredo HMAC seria aceito.

**Refresh token.** 256 bits, armazenado como SHA-256. O consumo é um `UPDATE ... WHERE used_at IS NULL RETURNING`: o mesmo comando resolve a corrida e detecta o replay, sem lock explícito e sem transação serializável.

**Replay.** Revoga a família inteira, encerra a sessão, audita. Consequência de UX declarada: dois refresh legítimos em paralelo derrubam a sessão.

**Rate limiting.** Dois eixos (conta e IP). Falha **fechada** em login, register e reset; **aberta** em refresh e logout. Timeout de 50 ms; resposta inesperada do Redis é tratada como indisponibilidade, nunca como "dentro do limite".

**TOTP.** Fase 1B.

**RLS.** O `sub` do token vira `app.user_id`. A consulta de sessão sob RLS faz duas coisas de uma vez: confirma que a sessão está viva e que o `sid` pertence ao `sub` — vínculo que a assinatura não prova.

**Segredos.** Nenhum no código, em migration ou em fixture. `AUTH_PEPPER` obrigatório em produção e obrigatoriamente diferente da KEK. A aplicação recusa iniciar se `DATABASE_AUTH_URL` não for `vlos_auth`.

---

## 6. Testes

**Não executados por mim.** Meu ambiente não tem rede, `npm install`, PostgreSQL nem Redis. Os números abaixo são de **blocos escritos**, não de execução:

```
Test Files : 14  (5 da Fase 0.5 + 9 da Fase 1A)
Tests      : 172 blocos it() no repositório
Passed     : NÃO EXECUTADO
Failed     : NÃO EXECUTADO
Skipped    : NÃO EXECUTADO
Todo       : 0 (nenhum bloco .todo em nenhuma suíte)
```

O que **foi** executado aqui: 24 asserções do domínio da Fase 1A (normalização, política de senha, tokens opacos, conjunto de chaves) e `tsc --strict --exactOptionalPropertyTypes` limpo nos módulos sem dependência externa.

`tools/check-test-results.mjs` produz o bloco exigido pelo item 41 e **falha o workflow** se houver skip, todo ou suíte obrigatória não coletada.

---

## 7. Testes de segurança

| Suíte | Blocos | Cobre |
|---|---|---|
| `authorization-confusion.spec.ts` | 12 | `sub` adulterado, reassinado, **`sid` de outro usuário**, sessão revogada, expirada, `is_admin` injetada, `role: admin`, `amr` forjada, acesso cruzado, autoelevação, funções de credencial, token sem `sid` |
| `auth-privileges.spec.ts` | 14 | `vlos_app` não lê `credential`, não executa as 3 funções, não lê `refresh_token`; `vlos_auth` não lê `credential`, `audit.log` nem `user`; sem `BYPASSRLS`, sem posse de tabela; guarda de RLS limpa |
| `connection-reuse.spec.ts` | 3 | Commit → outro usuário; rollback → outro usuário; sem contexto → zero linhas (pool `max: 1`) |
| `refresh.spec.ts` | 12 | Rotação, token anterior recusado, replay revoga família, **concorrência real repetida 20 vezes**, token bruto ausente de toda coluna |
| `jwt.spec.ts` | 13 | Os 8 ataques homologados |
| `rate-limit.spec.ts` | 10 | Limites, dois eixos e os 4 modos de falha do Redis |

O caso 3 da confusão de autorização é o central: token legitimamente nosso, `sub` correto, `sid` de outra pessoa. A assinatura não diz nada sobre isso — quem recusa é a policy de RLS.

---

## 8. Regressão da Fase 0.5

As 5 suítes originais estão preservadas, sem alteração de asserção. Um ponto de atenção declarado: `identity.organization` mantém o `GRANT INSERT` para `vlos_app` de propósito. Revogar seria mais limpo, mas mudaria a mensagem de erro de "RLS" para "permission denied" e quebraria um teste homologado da Fase 0.5. Nos dois casos a escrita é impossível; muda apenas qual camada recusa.

A guarda `ops.tables_missing_rls()` do `isolation.spec.ts` passa a cobrir as três tabelas novas — ela **é** o teste de regressão da `0008`.

---

## 9. Comandos executados

- `tsc --noEmit --strict --exactOptionalPropertyTypes --noUncheckedIndexedAccess` nos módulos sem dependência externa → **PASS**
- `tsx` executando 24 asserções do domínio → **24/24 PASS**
- `node --check` nas 3 ferramentas novas → **PASS**
- Verificação estrutural das 10 migrations (delimitadores, parênteses, `digest()` qualificado) → **PASS**
- Verificação de que nenhuma migration cria role com senha → **PASS**
- Verificação de ausência de `skipIf`, `.skip(`, `.todo(` nas 9 suítes da Fase 1A → **PASS**
- `diff -rq` entre workspace e pacote → idênticos

## 10. Comandos NÃO executados

`npm install`, `npm run lint`, `npm run typecheck`, `npm run build`, migrations contra PostgreSQL, seeds, e **todas as 14 suítes de teste**. Sem rede, sem Docker, sem PostgreSQL, sem Redis.

---

## 11. Limitações

1. **Nenhum teste foi executado.** É a limitação central.
2. **`env.spec.ts` foi modificado.** `DATABASE_AUTH_URL` passou a ser obrigatória, então a fixture precisou da variável. Nenhuma asserção existente foi enfraquecida ou removida; foram acrescentados 5 testes. Declaro explicitamente porque a regra proíbe alterar testes — e esta alteração é mudança de contrato, não conveniência de pipeline.
3. **Argon2 no CI.** 19456 KiB por verificação, dezenas de hashes na suíte. Pode exigir ajuste de `ARGON2_TIME_COST` no runner.
4. **`@node-rs/argon2` e `jose` nunca foram compilados aqui.** São as candidatas mais prováveis a erro de tipagem no próximo ciclo.
5. **Parâmetros do Argon2 não medidos.** `tools/bench-argon2.mjs` existe e precisa rodar no servidor real antes de fixar os valores.
6. **Sem teste HTTP de ponta a ponta.** As suítes exercitam serviços contra PostgreSQL e Redis reais, não o controller via HTTP — isso exigiria `@nestjs/testing` e `supertest`, adicionando duas dependências à matriz de versões. O `AuthGuard` é exercitado pela sua lógica equivalente na suíte de confusão de autorização.

---

## 12. Decisões arquiteturais

1. **Pepper por HMAC**, não pela opção `secret` da biblioteca — testável sem o módulo nativo e independente de fornecedor.
2. **SHA-256 no refresh token**, não Argon2 — 256 bits aleatórios não são enumeráveis; hash lento ali só custaria CPU.
3. **`0010` por lista branca**, não lista negra — a armadilha da `0005` mostra que lista negra só pega o que alguém lembrou de listar.
4. **`vlos_auth` sem acesso a `credential`** — nem a role de autenticação toca a tabela; só as três funções.
5. **Verificação de sessão a cada requisição** — janela zero de revogação, ao custo de uma consulta indexada dentro da transação que já seria aberta.
6. **Register devolve 202 sempre** — sem isso, o cadastro vira oráculo de existência.
7. **Senha verificada antes do bloqueio de conta** — conta bloqueada não pode ser detectável por tempo de resposta.
8. **Um `AuthService` e um `RefreshService`** em vez de sete arquivos de caso de uso — os fluxos compartilham as mesmas dependências e a separação criaria indireção sem ganho.

---

## 13. Itens adiados

`DEFERRED TO PHASE 1B`: recuperação de senha, verificação de e-mail, TOTP com códigos de recuperação, verificação de senha vazada (HIBP, exige rede de saída).
`DEFERRED — reavaliar com dados`: janela de graça no refresh concorrente.
`DEFERRED TO PHASE 2+`: veículos, propriedade, eventos, documentos, oficinas, IA.
`DEFERRED TO PHASE 9`: `audit.list_own_entries()`, role `vlos_audit_reader`.

---

## 14. Status

# ⛔ NOT READY FOR APPROVAL

Todos os critérios do item 40 relativos a **implementação** estão atendidos. Todos os critérios relativos a **execução** — typecheck, build, lint, migrations, testes, `Failed: 0`, `Skipped: 0` — estão **não verificados**, porque não consigo executá-los.

Declarar `IMPLEMENTATION COMPLETE` significaria afirmar que os testes passam. Eu não sei se passam. O que sei é que estão escritos, que não há skip nem todo, e que a suíte cobre o que foi homologado.

O status vira `IMPLEMENTATION COMPLETE — READY FOR INDEPENDENT REVIEW` quando o CI publicar o bloco do item 41 com `Failed: 0`, `Skipped: 0`, `Todo: 0`.
