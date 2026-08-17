# VEHICLE LIFE OS — Deploy e Operação

**Documentos F e J / Primeira Entrega**
Alvo: servidor dedicado próprio, Linux (Debian 12 ou Ubuntu 24.04 LTS)

---

## 1. Premissa e dimensionamento

O briefing diz que existe servidor dedicado (§43) e que não se deve assumir serverless. Concordo — para este perfil de carga (uploads, workers, banco relacional pesado), servidor dedicado é mais barato e mais previsível. Mas a §91 é igualmente importante: **servidor dedicado não é seguro por ser dedicado.**

Recurso mínimo estimado para o MVP com até ~5.000 veículos ativos:

| Serviço | vCPU | RAM | Observação |
|---|---|---|---|
| PostgreSQL | 2 | 4 GB | `shared_buffers` 25% da RAM dedicada |
| API | 1 | 1 GB | 2 réplicas |
| Worker | 1 | 2 GB | OCR e IA |
| Web (Next) | 1 | 1 GB | |
| Redis | 0,5 | 512 MB | `maxmemory-policy noeviction` (fila não pode perder job) |
| MinIO | 0,5 | 1 GB | |
| ClamAV | 1 | 2 GB | é o guloso; se a RAM for curta, usar serviço externo de scan |
| Observabilidade | 1 | 2 GB | Prometheus + Grafana |
| **Total** | **~8** | **~14 GB** | recomendo 8 vCPU / 32 GB / 2×NVMe em RAID 1 |

Disco: separar volumes de dados (`/var/lib/vlos/postgres`, `/var/lib/vlos/minio`) do sistema. LUKS no volume de dados.

---

## 2. Topologia de containers

```yaml
# infra/compose/docker-compose.prod.yml (esqueleto — arquivo real vem com a implementação)
networks:
  edge:      # exposta via Caddy
  internal:  # sem rota para a internet
    internal: true

services:
  caddy:
    image: caddy:2-alpine
    ports: ["80:80", "443:443"]
    networks: [edge]
    volumes: [caddy_data:/data, ./Caddyfile:/etc/caddy/Caddyfile:ro]

  api:
    image: vlos/api:${TAG}
    networks: [edge, internal]
    env_file: [.env.prod]
    deploy: { replicas: 2 }
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3000/health/live"]
      interval: 15s

  web:
    image: vlos/web:${TAG}
    networks: [edge, internal]

  worker:
    image: vlos/api:${TAG}
    command: ["node", "dist/worker.js"]
    networks: [internal]

  scheduler:
    image: vlos/api:${TAG}
    command: ["node", "dist/scheduler.js"]
    networks: [internal]

  postgres:
    image: postgres:16-alpine
    networks: [internal]          # NUNCA "ports:" (§92)
    volumes: [/var/lib/vlos/postgres:/var/lib/postgresql/data]

  redis:
    image: redis:7-alpine
    command: ["redis-server", "--requirepass", "${REDIS_PASSWORD}", "--maxmemory-policy", "noeviction"]
    networks: [internal]

  minio:
    image: minio/minio
    command: server /data
    networks: [internal]
    volumes: [/var/lib/vlos/minio:/data]

  clamav:
    image: clamav/clamav
    networks: [internal]
```

**Regras não negociáveis:**
- Nenhum serviço além do Caddy publica porta no host.
- Postgres, Redis, MinIO e ClamAV vivem só na rede `internal`, que não tem gateway para a internet.
- Todos os containers rodam como usuário não-root, com `read_only: true` e `cap_drop: [ALL]` onde possível.
- Imagens fixadas por digest, não por tag móvel.

**Caddyfile (essência):**

```
app.exemplo.com.br   { reverse_proxy web:3000 }
api.exemplo.com.br   { reverse_proxy api:3000 }
files.exemplo.com.br { reverse_proxy minio:9000 }   # domínio separado, sem cookies de sessão
admin.exemplo.com.br { reverse_proxy web:3000       # §93
  @blocked not remote_ip <FAIXAS_AUTORIZADAS>
  respond @blocked 404
}
```

---

## 3. Endurecimento do servidor (§91, §92)

```bash
# Firewall — só o essencial
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp        # de preferência, restrito ao seu IP
ufw allow 80,443/tcp
ufw enable

# SSH
# /etc/ssh/sshd_config:
#   PermitRootLogin no
#   PasswordAuthentication no
#   AllowUsers deploy
#   Port 22 (ou porta alta; segurança por obscuridade não substitui as linhas acima)

apt install -y fail2ban unattended-upgrades
systemctl enable --now fail2ban
dpkg-reconfigure -plow unattended-upgrades
```

Checklist adicional: usuário `deploy` sem sudo sem senha; auditd ligado; `/tmp` com `noexec`; sysctl endurecido (`net.ipv4.conf.all.rp_filter=1`, `kernel.dmesg_restrict=1`); NTP sincronizado (auditoria com relógio errado é auditoria inútil).

---

## 4. Segredos (§41)

MVP: arquivo `.env.prod` com permissão `600`, dono `deploy`, **fora do repositório**, com cópia lacrada em cofre de senhas. Fase 2: HashiCorp Vault ou Infisical auto-hospedado.

- Nenhum secret no Git — `gitleaks` no CI e no pre-commit.
- Chaves distintas por ambiente. Nunca reaproveitar chave de dev em produção.
- Rotação documentada: KEK anual ou sob incidente; JWT signing key trimestral (com janela de dois kids ativos); credenciais de banco semestral.
- `.env.example` versionado com todas as variáveis e descrição — sem valores.

---

## 5. Backup e restauração (§47)

**Banco — pgBackRest com WAL archiving:**

| Tipo | Frequência | Retenção | Destino |
|---|---|---|---|
| Full | Semanal (domingo 03:00) | 4 semanas | local + off-site |
| Incremental | Diário (03:00) | 14 dias | local + off-site |
| WAL contínuo | Streaming | 7 dias | off-site |

Resultado: **RPO ≈ 5 minutos** com PITR (restaurar para qualquer instante), não apenas para o último backup.

**Objetos (MinIO):** `restic` diário para destino off-site, cifrado, com retenção 30 dias / 6 meses / 3 anos.

**Off-site:** provedor diferente do servidor (Backblaze B2 ou S3), com credenciais **append-only** — se o servidor for comprometido, o atacante não consegue apagar os backups. Esse detalhe é a diferença entre sobreviver e não sobreviver a um ransomware.

**Cifragem:** backups cifrados com chave que **não** está no servidor. Guardada em cofre offline. Se a chave estiver na máquina, o backup cai junto com ela.

**Teste de restauração — obrigatório e agendado (§47):**

```
Mensal, primeira segunda-feira:
1. Provisionar container limpo
2. Restaurar último full + WAL para T-24h
3. Rodar suíte de verificação de integridade (contagens, hash chain da auditoria, amostragem de eventos)
4. Restaurar amostra de 100 objetos do MinIO e conferir sha256
5. Registrar tempo total em docs/restore-drills.md
6. Se RTO > 2h, tratar como defeito operacional
```

Alvos: **RPO 5 min · RTO 2 h.** Um backup nunca restaurado não conta como backup.

---

## 6. Monitoramento (§49)

**Health checks:** `/health/live` (o processo respira) e `/health/ready` (banco, Redis, MinIO respondem). O Docker usa `live`; o proxy usa `ready`.

**Métricas (Prometheus):** latência p50/p95/p99 por rota, taxa de erro 4xx/5xx, conexões e locks do Postgres, tamanho e idade das filas, jobs falhos, taxa de sucesso do OCR, custo de IA acumulado no dia, disco/CPU/RAM, idade do último backup.

**Alertas que acordam alguém:**

| Condição | Gravidade |
|---|---|
| Backup não concluído em 26 h | Crítico |
| Disco > 85% | Crítico |
| Fila com > 1.000 jobs pendentes ou job mais antigo > 30 min | Alto |
| Erro 5xx > 1% em 5 min | Alto |
| Cadeia de hash da auditoria quebrada | **Crítico — possível incidente de segurança** |
| Custo diário de IA > teto | Alto |
| Certificado expirando em < 14 dias | Médio |
| Pico de tentativas de login falhas | Alto |

**Logs:** Pino em JSON com `request_id` propagado por toda a cadeia (HTTP → caso de uso → job). Sem isso, depurar um OCR que falhou três horas depois é impossível. Retenção 30 dias quente, 12 meses frio.

---

## 7. Deploy e rollback (§91)

Pipeline: push → CI (lint, testes unitários, integração, segurança, build de imagem) → registry privado → deploy.

```
1. Backup do banco antes da migration
2. Migrations compatíveis com a versão anterior (expand → migrate → contract)
3. docker compose pull && up -d --no-deps api web worker
4. Health check; falhou → rollback automático para a tag anterior
5. Smoke tests em produção
6. Só depois, remoção de colunas antigas (fase "contract")
```

**Migrations nunca são destrutivas no mesmo deploy que o código.** Adicionar coluna → deploy do código que escreve nas duas → backfill → deploy do código que lê a nova → só então remover a antiga. É o que torna o rollback possível.

**Rollback:** `docker compose up -d` com a tag anterior. Se a migration precisar voltar, PITR para o instante anterior ao deploy — motivo pelo qual o passo 1 existe.

---

## 8. Recuperação de desastre (§48)

| Cenário | Ação | RTO |
|---|---|---|
| Container caiu | Restart automático (`restart: unless-stopped`) | < 1 min |
| Corrupção de dado por bug | PITR para o instante anterior | < 2 h |
| Disco falhou | RAID 1 assume; trocar disco | < 4 h |
| Servidor perdido | Provisionar novo, restaurar off-site, apontar DNS | < 8 h |
| Ransomware | Servidor novo + backup append-only não comprometido | < 12 h |

Runbook impresso e fora do servidor, contendo: onde estão as chaves de backup, ordem de restauração, contatos do provedor, procedimento de troca de DNS, e o comando exato de restore. Documentação de DR que só existe dentro do servidor perdido não é documentação de DR.

**Comunicação de incidente:** LGPD exige comunicação à ANPD e aos titulares em caso de incidente com risco relevante. O modelo de comunicado deve estar pronto **antes** de precisar dele.

---

## 9. Ordem de instalação no servidor (roteiro executável)

```
 1. Provisionar SO, criar usuário deploy, chaves SSH
 2. Endurecer SSH, ufw, fail2ban, unattended-upgrades
 3. LUKS no volume de dados; montar /var/lib/vlos
 4. Instalar Docker Engine + Compose plugin
 5. Apontar DNS (A/AAAA) para o servidor
 6. Clonar repositório em /opt/vlos
 7. Criar .env.prod a partir do .env.example (chmod 600)
 8. docker compose up -d postgres redis minio   → aguardar healthy
 9. Rodar migrations e seeds do catálogo
10. docker compose up -d api worker scheduler web caddy
11. Verificar TLS e cabeçalhos de segurança (testar externamente)
12. Configurar pgBackRest + restic + destino off-site
13. Executar o PRIMEIRO teste de restauração antes de qualquer dado real entrar
14. Subir Prometheus/Grafana/Alertmanager e validar um alerta de verdade
15. Criar primeiro usuário admin com MFA obrigatório
16. Registrar tudo em docs/deploy-log.md
```

O passo 13 é inegociável. Testar restauração depois que já existe dado de usuário é testar no lugar errado.
