# Givova Monitor — progresso da otimização e migração

Atualizado em 2026-09-21. Estado: implementação e validação local concluídas; produção não alterada.

## Guardrails preservados

- Agent 1.5.1 oficial mantido sem rebuild, substituição ou alteração de token.
- SHA-256 oficial: `e16bfc32798e4e395e28b0035bd27b2c9c3eedbdba8229776b914fbfc34a8288`.
- Agent 1.5.2 permanece somente como desenho; não foi construído nem publicado.
- Nenhum serviço Railway/PostgreSQL foi criado e nenhum cutover foi executado.
- Render, Aiven e R2 não foram desligados nem modificados por esta tarefa.

## Entregas por commit

| Commit | Entrega |
|---|---|
| `0cf594e` | Instrumentação agregada em memória de requests, bytes, latência, status, SQL e downloads. |
| `f39b259` | Caminho quente do report reduzido de 16–19 para no máximo 5 comandos SQL. |
| `6018d1d` | Polling por tela, redução em aba oculta, cancelamento, ETag/304 e gzip. |
| `2140f7d` | Download da release por redirect assinado direto ao R2. |
| `f94613e` | Docker/Gunicorn, runbook Railway e validação pós-restore do PostgreSQL. |
| `a87e29a` | Metadados oficiais alinhados à 1.5.1 e plano futuro da 1.5.2/domínio. |
| `f60ad12` | Resolução imediata de alertas preservada após a otimização de queries. |

## Antes e depois

As projeções abaixo usam 30 computadores. Valores de payload são corpos HTTP, sem estimar headers/TLS. O cenário backend atual mantém o intervalo do Agent 1.5.1 em aproximadamente 6 segundos.

| Métrica | Antes | Backend atual (1.5.1) | Futuro 1.5.2 planejado |
|---|---:|---:|---:|
| Reports/dia | 432.000 | 432.000 | 86.400 a cada 30s (-80%) |
| SQL/report comum aquecido | 16–19 | até 5 | alvo até 5 |
| SQL/dia | 6,9–8,2 milhões | até 2,16 milhões (-68,8% a -73,7%) | até 432 mil (-93,8% a -94,7%) |
| Respostas de heartbeat/dia | 55,3 MB | aproximadamente 55,3 MB | aproximadamente 3,7 MB com resposta de 43 B (-93,3%) |
| Request + response/dia | 369–392 MB | 369–392 MB | até 74–78 MB antes do ganho adicional de inventário/delta |
| Request + response/mês | 11,1–11,8 GB | 11,1–11,8 GB | até 2,2–2,4 GB antes de inventário/delta |

O cache é deliberadamente curto: regras, allowlists, configuração e reconciliações periódicas podem adicionar queries fora do report comum. As métricas agregadas devem ser usadas em produção para medir percentis e médias reais, sem criar uma linha de telemetria por request.

### Dashboard

Medição sintética com 30 dispositivos:

| Vista | Antes | Depois comprimido | Redução estimada |
|---|---:|---:|---:|
| Dashboard principal | 43,75 MB/h (`stats + devices` a cada 5s) | 0,110 MB/h (`stats` a cada 15s) | 99,75% |
| Computadores | 43,75 MB/h | 0,306 MB/h (`devices` a cada 15s) | 99,30% |
| Aba oculta | 43,75 MB/h | cerca de 0,014 MB/h para `stats` a cada 120s | 99,97% |

ETag/304 pode reduzir ainda mais quando o conteúdo não muda. O baseline de uma tela aberta por 8 horas era aproximadamente 350 MB; a tela principal passa a aproximadamente 0,88 MB no mesmo período.

### Releases

- Antes: cada download de 13.725.252 bytes atravessava o backend.
- Depois: o backend devolve um 302 curto; os bytes do executável seguem diretamente do R2 ao Agent 1.5.1.
- Uma distribuição para 30 máquinas deixa de transportar aproximadamente 411,8 MB de binário pelo backend, redução prática próxima de 100% para o corpo do executável.
- Timeout, 403/URL expirada, 404, redirect, hash e manutenção do executável atual foram cobertos por testes. O fallback legado continua controlado por configuração.

## Railway e PostgreSQL

O procedimento completo está em [RAILWAY_DEPLOY.md](RAILWAY_DEPLOY.md). O deploy usa o `Dockerfile`, Gunicorn em `0.0.0.0:$PORT`, `/health`, variáveis existentes e logs sem payload/token. Não foi criado `railway.json`: novos serviços devem usar a configuração atual da plataforma e, após existir um projeto, `.railway/railway.ts` se Config as Code for desejado.

A migração de dados está preparada como operação reversível:

1. congelar brevemente as escritas somente na janela aprovada;
2. gerar `pg_dump` custom-format do Aiven, sem apagar ou alterar a origem;
3. restaurar em um Railway PostgreSQL vazio;
4. executar `scripts/validate_postgres_migration.sql` na origem e no destino;
5. comparar tabelas, contagens exatas, PK/FK, índices, constraints, sequences e `MAX(id)`;
6. testar a aplicação Railway com URL temporária, mantendo Render/Aiven ativos;
7. somente após aceite, configurar o domínio permanente e planejar o cutover/rollback.

O projeto ainda usa `db.create_all()` e alterações manuais idempotentes; não existe uma cadeia Alembic completa. Por isso o dump/restore preserva o schema existente e a validação estrutural é obrigatória antes de qualquer troca de `DATABASE_URL`.

## Pendências externas — não executadas

1. Provisionar projeto/serviço e PostgreSQL no Railway.
2. Configurar variáveis reais via painel, sem copiá-las para arquivos ou logs.
3. Fazer build e smoke test do container em ambiente com Docker (o binário Docker não está disponível nesta estação).
4. Validar redirect/download contra o bucket R2 real e conferir novamente o SHA-256 oficial.
5. Fazer ensaio de `pg_dump`/`pg_restore` com credenciais reais e comparar os dois relatórios SQL.
6. Configurar `monitor.givovatransportes.com.br` somente após o ambiente temporário Railway passar pelos testes.
7. Observar métricas agregadas reais por pelo menos um ciclo representativo antes de decidir capacidade e cutover.
8. Implementar e validar o plano [AGENT_1_5_2_PLAN.md](AGENT_1_5_2_PLAN.md) em canary apenas após aprovação explícita.

## Validação local final

- 150 testes Python: aprovados.
- `tests/test_dashboard_polling.js`: aprovado.
- `tests/test_rollout_frontend.js`: aprovado.
- `git diff --check`: aprovado.
- Manifesto 1.5.1: conteúdo idêntico ao commit oficial após os testes.
