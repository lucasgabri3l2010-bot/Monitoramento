# Railway: preparação, ensaio e migração segura

Este documento prepara o Givova Monitor para Railway, mas **não autoriza o cutover**. Render, Aiven e R2 devem continuar ativos até que o ambiente Railway passe por todos os testes e uma janela de mudança seja aprovada.

## 1. Arquitetura de ensaio

- Serviço web Railway construído pelo `Dockerfile` da raiz.
- PostgreSQL Railway no mesmo projeto e ambiente.
- Cloudflare R2 existente, inicialmente com o mesmo bucket e credenciais.
- Domínio temporário `*.up.railway.app` durante a validação.
- Domínio permanente futuro: `https://monitor.givovatransportes.com.br`.
- Render e Aiven permanecem como produção durante todo o ensaio.

Não foi adicionado `railway.json`: Config as Code foi descontinuado para novos serviços em 2026. O `Dockerfile` raiz é detectado automaticamente; configure healthcheck e variáveis no serviço Railway ou gere a infraestrutura atual com `railway config init` depois que o projeto existir.

Referências oficiais: [Dockerfiles](https://docs.railway.com/builds/dockerfiles), [healthchecks](https://docs.railway.com/deployments/healthchecks), [Infrastructure as Code](https://docs.railway.com/config-as-code).

## 2. Criar o ambiente sem tráfego de produção

1. Crie um projeto e um ambiente de staging no Railway.
2. Adicione um serviço PostgreSQL, mas ainda não aponte o aplicativo para ele.
3. Adicione o repositório como serviço web. O Railway deve detectar `Dockerfile`.
4. Em Settings, configure `/health` como Healthcheck Path. O container escuta `0.0.0.0:$PORT` e o endpoint verifica uma consulta real ao banco.
5. Desative autodeploy de produção até o ensaio terminar. Não configure o domínio permanente nesta etapa.

O comando efetivo do container é:

```sh
python migrate.py && exec gunicorn --bind 0.0.0.0:${PORT} --workers 2 --threads 4 --error-logfile - servidor:app
```

`migrate.py` usa advisory lock no PostgreSQL, mas este projeto ainda usa `db.create_all()` e alterações manuais de schema; não existe uma cadeia Alembic. Isso exige dump, restore e validação disciplinados em toda mudança de banco.

## 3. Variáveis reais do serviço

Configure no Railway apenas variáveis consumidas pelo código. Nunca cole valores secretos em arquivos, commits, logs ou tickets.

Obrigatórias para o ensaio:

| Variável | Origem/valor |
|---|---|
| `DATABASE_URL` | Referência privada do PostgreSQL Railway, por exemplo `${{Postgres.DATABASE_URL}}` |
| `SECRET_KEY` | Novo segredo aleatório do ambiente Railway |
| `AGENT_SECRET_TOKEN` | Exatamente o token corporativo atual; não rotacionar durante a migração |
| `ADMIN_USERNAME` | Mesmo usuário administrativo previsto para o ambiente |
| `ADMIN_PASSWORD` | Segredo administrativo, armazenado somente nas Variables |
| `R2_ENDPOINT_URL` | Endpoint S3 do R2 existente |
| `R2_ACCESS_KEY_ID` | Credencial do R2 |
| `R2_SECRET_ACCESS_KEY` | Credencial do R2 |
| `R2_BUCKET_NAME` | `givova-monitor-releases` |

Configuração recomendada:

```dotenv
FLASK_ENV=production
SESSION_COOKIE_SECURE=true
DEMO_MODE=false
R2_REGION=auto
R2_DOWNLOAD_STRATEGY=redirect
R2_FALLBACK_TO_DATABASE=true
APP_TIMEZONE=America/Sao_Paulo
OFFLINE_THRESHOLD_SECONDS=30
CPU_ALERT_PERCENT=90.0
RAM_ALERT_PERCENT=90.0
DISK_ALERT_PERCENT=90.0
METRICS_RETENTION_DAYS=7
ACTIVITY_MONITORING_ENABLED=true
POLICY_MONITORING_ENABLED=true
DOMAIN_CLASSIFICATION_ENABLED=true
```

`PORT` é injetada pelo Railway. Não fixe uma porta diferente. `DATABASE_URL` aceita tanto `postgres://` quanto `postgresql://`; `config.py` normaliza o primeiro formato.

## 4. Ensaio Aiven para Railway PostgreSQL

Use clientes PostgreSQL da mesma versão principal ou mais recente que o servidor de origem. Trabalhe com variáveis de sessão; nunca escreva URLs completas em scripts ou no histórico compartilhado.

### 4.1 Capturar baseline da origem

Com `AIVEN_DATABASE_URL` definida somente no terminal local:

```sh
psql "$AIVEN_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f scripts/validate_postgres_migration.sql > aiven-before.txt
pg_dump "$AIVEN_DATABASE_URL" --format=custom --no-owner --no-acl --file=givova-aiven.dump
pg_restore --list givova-aiven.dump > givova-aiven.list.txt
```

O dump é somente leitura e não altera o Aiven.

### 4.2 Restaurar em uma base Railway vazia

Não inicie o web service contra essa base antes do restore, pois `migrate.py` criaria tabelas. Com `RAILWAY_DATABASE_PUBLIC_URL` definida localmente:

```sh
pg_restore --dbname="$RAILWAY_DATABASE_PUBLIC_URL" --no-owner --no-acl --exit-on-error --verbose givova-aiven.dump
psql "$RAILWAY_DATABASE_PUBLIC_URL" -X -v ON_ERROR_STOP=1 -f scripts/validate_postgres_migration.sql > railway-after.txt
```

Compare `aiven-before.txt` e `railway-after.txt`. Diferenças de contagem, constraints, índices ou sequências bloqueiam a continuação. A documentação oficial recomenda dump customizado e um restore drill: [Railway Back Up and Restore Postgres](https://docs.railway.com/guides/postgres-backups-restores).

Depois do restore validado, execute uma vez, apontando apenas para Railway:

```sh
DATABASE_URL="$RAILWAY_DATABASE_PUBLIC_URL" python migrate.py
```

Repita o script de validação. `migrate.py` pode adicionar schema idempotente e dados oficiais ausentes; qualquer mudança inesperada deve ser investigada antes de iniciar o web service.

## 5. Checklist funcional no domínio temporário

- `GET /health` retorna 200 e `database=connected`.
- `GET /health/db` retorna 200 e `engine=postgresql`.
- Login, dashboard, dispositivos, alertas, políticas e configurações funcionam.
- Um agente de laboratório 1.5.1 reporta usando o token atual.
- O report retorna o mesmo contrato, inclusive `idle_threshold_seconds`.
- O download 1.5.1 responde 302 e o arquivo final tem SHA-256 `e16bfc32798e4e395e28b0035bd27b2c9c3eedbdba8229776b914fbfc34a8288`.
- Logs não contêm payloads, tokens, URLs de banco ou URLs assinadas.
- Contadores agregados confirmam volume, latência, bytes e SQL/report.
- Reinício do serviço preserva todos os dados.

## 6. Domínio permanente e cutover futuro

Somente após aprovação:

1. Adicione `monitor.givovatransportes.com.br` em Public Networking.
2. Crie no provedor DNS os registros CNAME e TXT fornecidos pelo Railway; ambos são obrigatórios para verificação e TLS. Consulte [Working with Domains](https://docs.railway.com/networking/domains/working-with-domains).
3. Valide certificado, `/health`, login e report pelo domínio permanente.
4. Faça um dump final em janela controlada, restaure e repita todas as validações.
5. Mantenha Render e Aiven intactos para rollback. Não exclua, pause ou modifique o Aiven automaticamente.
6. Publique a migração de URL somente em uma futura versão 1.5.2 aprovada.

Rollback: remova o tráfego/DNS do Railway, continue usando o URL Render e descarte somente o ambiente Railway de ensaio após preservar logs de diagnóstico. Nenhuma escrita feita no Railway deve ser restaurada sobre o Aiven sem um plano de reconciliação aprovado.
