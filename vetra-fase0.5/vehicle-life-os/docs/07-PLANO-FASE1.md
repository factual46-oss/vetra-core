# VETRA — FASE 1 — PLANO REVISADO

**Status:** proposta revisada após revisão sênior. Nenhuma linha de código escrita.
**Base:** Fase 0.5, validada com 57 testes executados contra PostgreSQL real.
**Revisão:** 2 (19/08/2026)

---

## 1. Análise do estado atual

| Item | Achado | Consequência |
|---|---|---|
| `queryUnscoped` / `transactionUnscoped` | **Zero chamadas** em todo o código | A regra "dado de usuário só por `withUserContext`" nasce sem dívida |
| `withUserContext` | Implementado, valida UUID, `set_config(..., is_local => true)` | Ponto único de integração da identidade |
| `identity."user"` | Sem qualquer coluna de credencial | Credenciais nascem em tabela própria |
| RLS em `identity."user"` | `SELECT`/`UPDATE` do próprio usuário; **nenhuma policy de `INSERT`** | Cadastro e login exigem `SECURITY DEFINER` |
| `audit.log` | `INSERT` apenas, sem `SELECT`, sem `RETURNING` | Eventos de auth entram sem contexto. Nada a mudar |
| `ops.tables_missing_rls()` | 0 linhas | Toda tabela nova precisa de RLS ou isenção justificada |

---

## 2. ALTERAÇÕES APÓS REVISÃO SÊNIOR

| # | Ponto levantado | O que muda | Justificativa |
|---|---|---|---|
| 1 | **D1/D2 se contradizem**: `authenticate_lookup` devolve o hash a `vlos_app` | Seção 4 reescrita com três alternativas avaliadas em sete dimensões, e recomendação fundamentada. A afirmação original foi **retirada** | A crítica procede. Tirar o `SELECT` da tabela e devolver o mesmo dado por função executável pela mesma role não reduz a superfície — só muda o guichê. Uma injeção pode chamar a função em laço e extrair a base inteira |
| 2 | JWT/chaves sem detalhe | Seção 6: armazenamento, conjunto `current`/`next`, `kid`, rotação em quatro tempos, período de graça, retirada, `kid` desconhecido, oito testes de adulteração | Rotação sem período de graça definido derruba todos os tokens vivos no momento da troca |
| 3 | Falta teste real de concorrência no refresh | Seção 7: teste com duas requisições simultâneas de verdade e teste que prova que o token bruto nunca é gravado | Corrida em rotação de token é onde a maioria das implementações falha, e não aparece em teste sequencial |
| 4 | Redis: comportamento genérico demais | Seção 9: matriz **por endpoint**, com quatro modos de falha testados separadamente | "Falha fechado" como regra única transformaria queda do Redis em logout global. Refresh e logout precisam de tratamento oposto ao do login |
| 5 | TOTP subespecificado | Seção 10: RFC 6238, vetores oficiais, timestep, janela, zeros à esquerda, replay, relógio, rate limit | Zero à esquerda é o defeito clássico de implementação de TOTP e só aparece em ~10% dos códigos |
| 6 | Argon2id sem benchmark | Seção 11: `tools/bench-argon2.mjs`, metas de latência e memória, parâmetros configuráveis e versionados por linha | Parâmetro de Argon2 sem medição no hardware real é chute — pode derrubar o servidor ou ser fraco demais |
| 7 | Faltam testes de confusão de autorização | Seção 13: suíte dedicada com 12 casos | Adulteração de `sub`/`sid` e autoelevação por claim são a falha mais comum em JWT |
| 8 | Janela de revogação implícita | Seção 12: decisão explícita de verificação por requisição, com a janela declarada em número | "O token vale até expirar" é consequência que ninguém deve descobrir durante um incidente |

---

## 3. O problema de evidência — inalterado

O Gate 1 exige `Failed: 0 / Skipped: 0` de testes **executados**. Meu ambiente não tem rede, `npm install`, Docker nem PostgreSQL. Entrego código e testes; a execução é no seu CI, e meu relatório dirá `NOT READY FOR APPROVAL` até a esteira publicar os números.

---

## 4. D1 REVISADO — onde a senha é verificada

### 4.1 O problema, enunciado corretamente

O Argon2id roda em Node. Para verificar uma senha, alguém precisa do hash. Se quem verifica é a aplicação, o hash chega até ela — e qualquer execução de SQL arbitrário com a role da aplicação consegue o mesmo, chamando a função de lookup em laço.

A pergunta real não é "como esconder o hash", e sim: **quanto vale, para o atacante, o que ele consegue extrair?**

### 4.2 Alternativa A — verificar dentro do PostgreSQL (pgsodium / pg_argon2)

`identity.verify_password(email, senha_em_claro) → uuid`, `SECURITY DEFINER`, usando Argon2id nativo do libsodium via extensão. O hash nunca sai do banco.

| Dimensão | Avaliação |
|---|---|
| Superfície de ataque | Menor em extração: injeção não obtém hash. Mas cria um **oráculo de verificação** — a função aceita palpites, ao custo de ~100ms cada, fora do alcance do rate limit da aplicação |
| Privilégio necessário | `EXECUTE` para `vlos_app`. Instalação da extensão exige superusuário no bootstrap |
| Impacto em SQL injection | **Alto ganho**: sem hash, não há ataque offline. Resta ataque online, lento e auditável |
| Complexidade | **Alta.** `postgres:16-alpine` não traz pgsodium nem pg_argon2 → imagem customizada, rebuild a cada atualização do Postgres, responsabilidade própria por patches de segurança do banco |
| Desempenho | **Ruim.** Move ~19 MiB e ~100ms de CPU por login para o servidor de banco — o componente mais difícil de escalar horizontalmente. Um pico de logins compete com as consultas de todo o resto |
| Impacto operacional | Senha em claro trafega até o banco. Com `log_min_duration_statement` e `log_parameter_max_length` mal configurados, a senha vai parar no log do Postgres. Exige revisão explícita da configuração e vira item permanente de runbook |
| Testabilidade | Boa para o comportamento; ruim para o ambiente — o CI passa a depender de imagem customizada |

### 4.3 Alternativa B — role dedicada `vlos_auth` + pepper na aplicação

Duas mudanças combinadas:

1. **Role dedicada.** `vlos_auth` recebe `EXECUTE` apenas nas funções de credencial e **nada mais** — nenhuma tabela, nenhum outro schema. Um pool de conexão separado, usado exclusivamente pelo módulo de autenticação. `vlos_app` perde o `EXECUTE` sobre essas funções.
2. **Pepper.** Antes do Argon2, a senha passa por `HMAC-SHA256(pepper, senha)`, com o pepper vindo de `APP_PASSWORD_PEPPER` — variável de ambiente, nunca no banco.

| Dimensão | Avaliação |
|---|---|
| Superfície de ataque | Injeção em qualquer módulo que não seja o de auth — ou seja, todo o produto futuro: veículos, eventos, documentos — **não alcança credencial alguma**. Resta o módulo de auth, cujo SQL é inteiramente parametrizado e tem superfície mínima |
| Privilégio necessário | Uma role a mais, estritamente **menos** privilegiada que `vlos_app` |
| Impacto em SQL injection | **Alto ganho por dois caminhos independentes.** Redução de alcance (só o módulo de auth chega lá) e redução de valor: hash extraído sem o pepper é inútil para ataque offline, porque falta uma chave de 256 bits que não está no banco |
| Complexidade | **Baixa.** Um pool a mais, um `GRANT`/`REVOKE`, uma chave a mais no `.env` |
| Desempenho | Argon2 continua na camada de aplicação, que escala horizontalmente. Custo do HMAC: microssegundos |
| Impacto operacional | O pepper vira material crítico de backup: perdê-lo invalida todas as senhas. Precisa de procedimento de custódia e de rotação (com re-hash no login seguinte) |
| Testabilidade | **Ótima.** É tudo testável contra PostgreSQL real: `vlos_app` não consegue executar a função; `vlos_auth` não consegue ler nenhuma tabela; hash sem pepper não confere |

### 4.4 Alternativa C — manter como está, assumindo o risco

`authenticate_lookup` continua executável por `vlos_app`, sem pepper e sem role dedicada.

| Dimensão | Avaliação |
|---|---|
| Superfície de ataque | Qualquer injeção em qualquer módulo, agora ou no futuro, extrai a base de hashes |
| Privilégio necessário | Nenhum a mais |
| Impacto em SQL injection | **Nenhum ganho.** Argon2id torna o ataque offline caro, não inviável — senhas fracas caem |
| Complexidade | Zero |
| Desempenho | Melhor de todos |
| Impacto operacional | Nenhum |
| Testabilidade | Boa |

### 4.5 Recomendação: Alternativa B

Não é a mais simples, e é essa a razão de a comparação existir. A ordenação por risco residual é A < B < C; a ordenação por custo operacional é C < B << A.

A recomendação é B porque **A compra pouco a mais que B a um custo desproporcional**: A elimina a extração do hash, mas cria um oráculo de verificação online, empurra o Argon2 para dentro do banco e exige imagem customizada do PostgreSQL para sempre. B chega perto do mesmo resultado prático — o hash extraído deixa de valer sem o pepper — por um pool e uma variável de ambiente.

A avaliação honesta de B: ela **não** torna o hash inextraível. Uma injeção dentro do módulo de auth ainda alcança a função. O que ela faz é (i) tirar o alcance de todo o resto do sistema, que é onde o código vai crescer, e (ii) tirar o valor do que for extraído. Isso é o que vou afirmar na documentação — nada além.

**Se preferir A**, é uma escolha defensável e eu implemento; o custo é imagem própria do PostgreSQL e revisão da configuração de log do banco como item permanente de operação.

---

## 5. D2 — funções `SECURITY DEFINER` (revisada para a Alternativa B)

| Função | Executável por | Motivo de existir |
|---|---|---|
| `identity.register_user(...)` | `vlos_auth` | Não há policy de `INSERT` em `user`, e não deve haver |
| `identity.authenticate_lookup(email_norm)` | `vlos_auth` | Login precisa achar o usuário antes de existir contexto |
| `identity.set_password(user_id, hash, params, motivo)` | `vlos_auth` | `credential` é inacessível a qualquer role de aplicação |
| `identity.consume_single_use_token(kind, hash)` | `vlos_auth` | Consumo atômico, resistente a corrida |

Todas: owner `vlos_migrator`, `SET search_path` fixo, objetos qualificados, `REVOKE ALL FROM PUBLIC`, `GRANT EXECUTE` só a `vlos_auth`, testes de abuso.

`authenticate_lookup` para e-mail inexistente retorna vazio, e a aplicação executa mesmo assim uma verificação Argon2 contra um hash fixo, para não criar diferença grosseira de tempo.

**Sobre "não criar uma segunda forma de acesso ao banco" (item 2 do prompt):** `vlos_auth` é estritamente **menos** privilegiada que `vlos_app` — sem tabelas, sem schemas, só quatro funções. Não é uma segunda porta larga; é uma fresta com escopo menor que a porta existente.

---

## 6. D3 — Access token e gestão de chaves

### 6.1 Token

| Aspecto | Escolha |
|---|---|
| Algoritmo | **EdDSA (Ed25519)** via `jose`, whitelist explícita `algorithms: ['EdDSA']` |
| Duração | 10 minutos |
| Claims | `iss`, `aud`, `sub` (= `identity.user.id`), `sid`, `jti`, `iat`, `exp`, `amr` |
| Fora do token | e-mail, nome, papel, permissão administrativa, qualquer dado pessoal |

Autorização administrativa **nunca** vem do token: `admin_permission` é consultada no banco, sob RLS, a cada uso.

### 6.2 Armazenamento da chave privada

- `JWT_KEYS_JSON`: array `[{ kid, privatePem, publicPem, status, notBefore }]`, em variável de ambiente. Arquivo `.env.prod` com modo `600`, fora do Git, coberto por `gitleaks`.
- Carregada uma vez no boot, mantida em memória. `JWT_KEYS_JSON` e `privatePem` entram na lista de redação do logger.
- Validação de inicialização (item 23): em produção o processo **não sobe** se o conjunto estiver vazio, se não houver exatamente uma chave `active`, se algum `kid` repetir, se a chave não for Ed25519 válida, ou se algum PEM tiver menos de 100 bytes.
- Evolução registrada: migrar para secret manager na Fase 10.

### 6.3 Conjunto de chaves e `kid`

`status` ∈ `active` (assina e verifica) · `next` (só verifica) · `retiring` (só verifica).
Assinatura sempre com a única `active`, cujo `kid` vai no header. Verificação resolve pela `kid`.

### 6.4 Rotação em quatro tempos

| Tempo | Ação | Espera mínima |
|---|---|---|
| T0 | Gerar par novo, entrar como `next` (só verificação) | — |
| T1 | Promover `next` → `active`; a anterior vira `retiring` | ≥ 1 ciclo de deploy, para todas as instâncias conhecerem a chave |
| T2 | `retiring` continua verificando — **período de graça** | **1 hora** (6× o TTL de 10 min) |
| T3 | Remover a `retiring` do conjunto | — |

Cadência: trimestral, e imediata em caso de suspeita — nesse caso o período de graça é zero e todos os tokens vivos morrem, que é o objetivo.

O período de graça de 1 hora existe porque, sem ele, a promoção invalidaria instantaneamente todo token assinado pela chave anterior: até 10 minutos de erros 401 em massa. Uma hora é folga confortável sobre o TTL sem manter chave velha viva por tempo relevante.

### 6.5 `kid` desconhecido

401 com o mesmo corpo genérico de qualquer token inválido — sem dizer que o `kid` é o problema. Evento de auditoria `AUTH_TOKEN_UNKNOWN_KID` com o `kid` recebido (não é segredo) e métrica própria: um pico aqui significa chave retirada cedo demais ou token forjado.

### 6.6 Testes de adulteração (8)

1. payload alterado, assinatura original → 401
2. assinado com chave Ed25519 estranha → 401
3. `alg: none` → 401
4. **`alg: HS256` usando a chave pública como segredo HMAC** — o ataque clássico de confusão de algoritmo → 401
5. `kid` inexistente → 401 + evento de auditoria
6. `kid` de outra chave do conjunto → 401 (assinatura não confere)
7. `exp` no passado → 401
8. `iss`/`aud` incorretos → 401

---

## 7. D4 — Refresh token

32 bytes de `randomBytes`, base64url, gravado como **SHA-256**.

**Por que SHA-256 e não Argon2** (a escolha parece contradizer a seção 4): Argon2 protege segredos de **baixa entropia**, onde o atacante enumera o espaço de busca. 256 bits aleatórios não são enumeráveis; hash lento ali só custa CPU em toda renovação. O que protege o refresh token é entropia, rotação e detecção de replay.

Consumo atômico:

```sql
UPDATE identity.refresh_token SET used_at = now()
 WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL
 RETURNING session_id, family_id
```

Zero linhas + token existente com `used_at` preenchido = **replay** → revoga a família inteira, encerra a sessão, audita, força novo login.

### 7.1 Teste de concorrência (obrigatório)

```
Promise.all([ refresh(A), refresh(A) ])   // mesmo token, simultâneos
  → exatamente um 200 e exatamente um 401
  → família revogada, sessão encerrada
  → evento REFRESH_REPLAY_DETECTED na auditoria
```

Executado com o mesmo token bruto, sem serialização artificial, repetido 20 vezes para pegar instabilidade. O `UPDATE` condicional é o que garante o resultado: o segundo `UPDATE` não encontra linha, sem lock explícito e sem transação serializável.

**Consequência de UX, declarada:** um cliente que dispare dois refresh legítimos em paralelo — app móvel com duas telas renovando ao mesmo tempo — cai como replay e perde a sessão. A política estrita é a decisão da revisão sênior e será documentada como comportamento esperado. A alternativa comum (janela de graça de alguns segundos devolvendo o mesmo token novo) fica registrada como **DEFERRED**, para reavaliação com dados reais de suporte.

### 7.2 Teste de que o token bruto nunca é gravado

Após um refresh bem-sucedido, uma consulta pela role `vlos_migrator` percorre **todas as colunas de texto e bytea** de `identity.refresh_token` e afirma que a string bruta não aparece em nenhuma delas, e que `token_hash = sha256(bruto)` casa em exatamente uma linha.

---

## 8. D5 — Transporte e CSRF

Cookie `HttpOnly; Secure; SameSite=Lax; Path=/api` para o web (via BFF) e `Authorization: Bearer` para mobile e B2B. Mesma emissão, transporte escolhido por cabeçalho.

**CSRF, sem marcar caixinha:** o vetor existe só no modo cookie, porque só ele é enviado automaticamente pelo navegador. Proteção: `SameSite=Lax` **mais** double-submit token em toda rota mutante — `SameSite` sozinho não cobre navegador antigo nem subdomínio comprometido. No modo Bearer o vetor não existe: nada anexa o cabeçalho sem o JavaScript da própria aplicação.

---

## 9. D6 — Rate limiting e comportamento do Redis por endpoint

### 9.1 Limites

| Endpoint | Limite | Chaves |
|---|---|---|
| `POST /auth/register` | 5 / hora | IP |
| `POST /auth/login` | 5 / 15 min · 20 / 15 min | e-mail normalizado · IP |
| `POST /auth/refresh` | 60 / hora | `sid` |
| `POST /auth/password-reset` | 3 / hora · 10 / hora | e-mail · IP |
| `POST /auth/totp/verify` | 5 / 5 min | `user_id` |

Dois eixos porque limitar só por IP é contornável com rotação, e limitar só por conta permite negar serviço a um usuário legítimo. Bloqueio temporário e crescente, teto de 15 minutos, **nunca permanente**.

### 9.2 Comportamento quando o Redis não responde

Uma regra única seria errada: falhar fechado no refresh derrubaria todas as sessões do produto em uma queda de Redis; falhar aberto no login entregaria brute force livre.

| Endpoint | Redis indisponível | Por quê |
|---|---|---|
| `POST /auth/login` | **503, falha fechada** | O rate limit é a única defesa contra brute force de senha |
| `POST /auth/totp/verify` | **503, falha fechada** | Seis dígitos são 10⁶ — sem limite, o segundo fator vira decorativo |
| `POST /auth/password-reset` | **503, falha fechada** | Envia e-mail e é adjacente a enumeração |
| `POST /auth/register` | **503, falha fechada** | Sem limite, criação de contas em massa |
| `POST /auth/refresh` | **Falha aberta**, com `WARN` e evento de auditoria | O chamador já precisa possuir um refresh token válido, de uso único e verificado no banco. Falhar fechado transformaria queda de Redis em logout global em 10 minutos |
| `POST /auth/logout` | **Falha aberta** | Revogar é sempre seguro permitir |
| Verificação de sessão revogada | **Cai para consulta ao PostgreSQL** | Sem janela de revogação (seção 12) |

Toda operação de rate limit tem **timeout duro de 50ms**; estouro conta como indisponível.

### 9.3 Quatro modos de falha, testados separadamente

| Modo | Como é reproduzido | Esperado |
|---|---|---|
| Connection refused | Cliente apontado para porta fechada, real | Login 503; refresh 200 |
| Timeout | Servidor TCP de teste que aceita e nunca responde | Corte em 50ms, mesmo comportamento |
| Indisponibilidade no meio do fluxo | Conexão derrubada entre duas chamadas | Sem 500; classificação correta |
| Resposta inválida | Stub que devolve tipo inesperado | Tratado como indisponível, não como "dentro do limite" |

O último é o mais importante e o mais esquecido: uma resposta inesperada interpretada como "ok" desliga o rate limit em silêncio. Aqui o mock é legítimo — não substitui segurança de banco, e sim simula falha de infraestrutura (item 32).

---

## 10. D7 — TOTP

| Aspecto | Especificação |
|---|---|
| Padrão | **RFC 6238** (TOTP) sobre RFC 4226 (HOTP), HMAC-SHA1 |
| T0 / timestep | T0 = 0, X = **30s** |
| Dígitos | **6** em produção |
| Truncamento | Dinâmico, conforme RFC 4226 §5.3 |
| **Zeros à esquerda** | `String(code).padStart(6, '0')` — cerca de 10% dos códigos começam com zero, e comparar como número é o defeito clássico. Há teste dedicado |
| Janela | **±1 step** (aceita T−1, T, T+1) ≈ 90s de tolerância |
| Replay | `last_used_step` por usuário; step ≤ último é recusado, mesmo dentro da janela |
| Relógio | Servidor sincronizado por NTP (já no Doc 04). A janela ±1 cobre ~30s de deriva do aparelho; deriva maior exige ressincronizar o dispositivo — mensagem de erro orienta isso sem revelar se o código estava próximo |
| Rate limit | 5 tentativas / 5 min por usuário, bloqueio de 15 min, cada falha auditada |
| Segredo | AES-256-GCM com a `APP_KEK`, nunca em claro no banco, nunca em log |
| Desativação | Exige senha **e** código TOTP válido (item 17) |
| Recuperação | 10 códigos de uso único, SHA-256 |

**Vetores oficiais:** o Apêndice B da RFC 6238 publica códigos de **8 dígitos** com a seed `12345678901234567890`. A suíte testa exatamente esses valores em modo 8 dígitos — provando o algoritmo contra o padrão — e testa separadamente o truncamento para 6 dígitos usado em produção.

---

## 11. D8 — Argon2id: parâmetros e benchmark

### 11.1 Configuráveis e versionados

`ARGON2_MEMORY_KIB`, `ARGON2_TIME_COST`, `ARGON2_PARALLELISM`, validados na inicialização contra o mínimo OWASP (m ≥ 19456 KiB, t ≥ 2, p ≥ 1). Ponto de partida: **m = 19456 KiB, t = 3, p = 1**.

Os parâmetros usados são gravados **por linha** em `identity.credential`. No login seguinte, se os parâmetros da linha forem inferiores aos atuais, a senha é re-hasheada após verificação bem-sucedida. Isso permite endurecer o custo sem invalidar senha alguma.

### 11.2 Benchmark — `tools/bench-argon2.mjs`

Mede, no hardware real:

| Métrica | Meta |
|---|---|
| Latência de hash (1 requisição) | ≤ 250 ms |
| Latência de verify (1 requisição) | ≤ 250 ms |
| Latência sob 8 logins simultâneos | ≤ 1 s no p95 |
| Pico de RSS | `m × p × concorrência` deve caber com folga na RAM da API |
| Concorrência testada | 1, 4, 8, 16, 32 |

Roda contra 1, 4, 8, 16 e 32 requisições paralelas e imprime uma tabela. **O resultado no seu servidor decide os parâmetros finais** — os valores acima são ponto de partida, não conclusão. O benchmark não entra no caminho crítico do CI: é comando manual, com a saída registrada no documento de decisões.

Risco declarado: com m = 19456 KiB e 32 logins simultâneos, o pico é ~620 MiB só de Argon2. O limite de concorrência da API precisa considerar isso, ou um pico de login vira OOM.

---

## 12. D9 — Revogação de sessão e janela do access token

**A consequência, declarada em número antes da decisão:** um access token é autoverificável. Sem consulta a estado, revogar a sessão **não** invalida os tokens já emitidos — eles continuam válidos até `exp`. Com TTL de 10 minutos, a janela seria de **até 10 minutos** entre o logout e a perda real de acesso.

Para este produto isso é inaceitável em revogação por comprometimento. **Decisão: verificação de estado da sessão a cada requisição.**

| Caminho | Custo | Janela |
|---|---|---|
| Normal | Lista de revogação no Redis, `GET` por `sid`, TTL igual ao do access token | **0** |
| Redis indisponível | Consulta indexada a `identity.session.revoked_at` no PostgreSQL, na mesma transação de `withUserContext` | **0** |
| Ambos indisponíveis | Não há requisição sendo servida | — |

Custo real: um `GET` sub-milissegundo por requisição, ou uma consulta indexada na transação que já seria aberta. A janela de 10 minutos fica registrada aqui como a consequência do modelo puramente stateless que **não** adotamos — para que ninguém a redescubra durante um incidente.

Revogação imediata dispara também em: troca de senha, desativação de TOTP, replay detectado e "sair de todas as sessões".

---

## 13. D10 — Integração com RLS e testes de confusão de autorização

```
request → AuthGuard → AuthContext → withUserContext(sub) → SET LOCAL app.user_id → RLS
```

O `sub` **é** o `identity.user.id`. Nenhum segundo identificador. Regra de lint proíbe `queryUnscoped`/`transactionUnscoped` fora de `infra/` e `health` — hoje há zero chamadas, então a regra entra sem exceções.

### Suíte `security/authorization-confusion.spec.ts` (12 casos)

| # | Ataque | Esperado |
|---|---|---|
| 1 | `sub` trocado para outro usuário, assinatura original | 401 |
| 2 | `sub` trocado e reassinado com chave estranha | 401 |
| 3 | `sid` trocado para sessão de outro usuário | 401 — **o guard exige que o `sid` pertença ao `sub`** |
| 4 | `sid` de sessão revogada | 401 |
| 5 | `sid` de sessão expirada | 401 |
| 6 | Claim `is_admin: true` injetada | Ignorada; `admin_permission` vem do banco |
| 7 | Claim `role: "admin"` injetada | Idem |
| 8 | `amr: ["pwd","otp"]` forjada sem TOTP | Rotas que exigem 2FA recusam |
| 9 | Token válido de A pedindo dado de B | Zero linhas (RLS) |
| 10 | `INSERT` direto em `admin_permission` pela role da aplicação | Permissão negada (regressão do AUD-09) |
| 11 | Chamada a `authenticate_lookup` pela role `vlos_app` | Permissão negada (Alternativa B) |
| 12 | Token sem `sid` | 401 |

O caso 3 é o que quase todo mundo esquece: validar a assinatura prova que o token foi emitido por nós, não que aquele `sid` é daquele `sub`.

---

## 14. Migrations (aditivas)

**`0008_identity_auth.sql`** — tabelas, RLS, policies, grants:

| Tabela | Acesso da aplicação |
|---|---|
| `identity.credential` | RLS sem policy, sem grant — só `SECURITY DEFINER` via `vlos_auth` |
| `identity.session` | `SELECT`/`UPDATE` onde `user_id = ops.current_user_id()` |
| `identity.refresh_token` | Sem policy de leitura; consumo por função |
| `identity.mfa_totp` | `SELECT` do próprio usuário |
| `identity.recovery_code` | Idem |
| `identity.single_use_token` | Sem policy — só `SECURITY DEFINER` |

**`0009_identity_functions.sql`** — as quatro funções, com owner, `search_path` e grants restritos a `vlos_auth`.

**`0010_auth_role.sql`** — criação de `vlos_auth` (sem tabela, sem schema, só `EXECUTE`) e `REVOKE` das funções de `vlos_app`.

`ops.tables_missing_rls()` verificado em zero ao final. Nenhuma migration histórica é editada.

---

## 15. Plano de testes

**86 a 98 testes novos.** Zero `skipIf` nas suítes da Fase 1: sem banco elas **falham**, não pulam.

| Suíte | Casos |
|---|---|
| `auth/registration.spec.ts` | ~10 |
| `auth/login.spec.ts` | ~14 (anti-enumeração: corpo e forma idênticos) |
| `auth/session.spec.ts` | ~10 |
| `auth/refresh.spec.ts` | ~14 (inclui concorrência real e token bruto ausente do banco) |
| `auth/jwt-keys.spec.ts` | ~10 (rotação, graça, `kid` desconhecido, 8 adulterações) |
| `auth/recovery.spec.ts` | ~10 |
| `auth/totp.spec.ts` | ~14 (vetores RFC 6238, zero à esquerda, replay, deriva) |
| `auth/rate-limit.spec.ts` | ~12 (limites + 4 modos de falha do Redis) |
| `security/authorization-confusion.spec.ts` | **12** |
| `security/connection-reuse.spec.ts` | **3** (pool `max: 1`) |
| `security/auth-audit.spec.ts` | ~8 (eventos existem, nenhum contém segredo, cadeia íntegra) |

---

## 16. Dependências novas

| Pacote | Versão | Por quê |
|---|---|---|
| `@node-rs/argon2` | `^2.0.2` | Binários pré-compilados; o `argon2` clássico exige `node-gyp` e quebra em Alpine |
| `jose` | `^5.9.6` | JOSE puro, sem nativo, EdDSA |
| `@fastify/cookie` | `^9.4.0` | **v9 = Fastify 4.** v10+ é Fastify 5 — exatamente o erro do `@fastify/helmet` |

Rate limiting e TOTP implementados internamente, sem pacote.

---

## 17. Divisão da entrega

**Fase 1A** — registro, login, Argon2id + benchmark, `vlos_auth` + pepper, sessão, access token e gestão de chaves, refresh com rotação e replay, logout, rate limiting, anti-enumeração, auditoria, RLS, confusão de autorização, reutilização de conexão. (~60 testes)

**Fase 1B** — recuperação de senha, verificação de e-mail, TOTP com códigos de recuperação. (~35 testes)

Cada ciclo de CI valida metade do volume, e um erro de tipagem no TOTP não impede a validação do login.

---

## 18. Fora de escopo

`DEFERRED TO PHASE 2+`: veículos, propriedade, eventos, documentos, OCR, oficinas, IA, score, marketplace, transferência, dashboard.
`DEFERRED TO PHASE 9`: `audit.list_own_entries()`, role `vlos_audit_reader`.
`DEFERRED — reavaliar com dados`: janela de graça no refresh concorrente (seção 7.1).
Nenhum dado veicular fictício será criado.
