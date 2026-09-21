# Agent 1.5.2: plano de protocolo e migração de URL

Status: **somente desenho**. Não construir, assinar, publicar nem promover a versão 1.5.2 sem aprovação formal. O Agent 1.5.1 e seu SHA-256 oficial permanecem imutáveis.

## Objetivos

- Reduzir o heartbeat de aproximadamente 6s para 30s.
- Separar inventário estático de telemetria mutável.
- Preservar histórico, alertas, políticas e autoridade do servidor.
- Migrar somente o endpoint Render conhecido para o domínio permanente.
- Fazer download direto do R2 sem encaminhar tokens corporativos ao host de objetos.

## Protocolo proposto

### Heartbeat/telemetria

- `interval_seconds`: 30s, com jitter pequeno por dispositivo para evitar rajadas.
- Enviar UUID, versão, CPU, RAM, disco, uptime, estado de sessão, idle e atividade atual.
- O backend continua aceitando integralmente payloads 1.5.1 a cada 5–6s.
- Em falha, usar backoff exponencial limitado; ao recuperar, enviar apenas o estado atual, sem reproduzir centenas de heartbeats.
- O servidor continua gravando `metrics_history`; a menor frequência reduz naturalmente o volume de linhas.

Com 30 PCs, 30s produz aproximadamente 86.400 reports/dia, contra 432.000 a 6s.

### Inventário estático

Separar hostname, SO, arquitetura, processador, núcleos, RAM total, disco total e MAC. Calcular SHA-256 de JSON canônico com chaves ordenadas e tipos normalizados.

Enviar inventário quando:

1. o agente inicia e ainda não possui fingerprint confirmado;
2. o fingerprint muda;
3. passaram 24 horas desde a última confirmação;
4. o servidor solicita `inventory_required=true`.

Persistir localmente somente fingerprint e timestamps, nunca token em arquivo novo. O backend deve aceitar payload completo antigo e delta novo durante toda a transição.

### Resposta mínima

Para 1.5.2, responder apenas campos necessários:

```json
{"status":"ok","idle_threshold_seconds":300}
```

Campos de compatibilidade (`message`, `device_id`, `status_computed`) permanecem para 1.5.1. Uma futura negociação pode usar `X-Agent-Protocol: 2`; não inferir por User-Agent.

## Migração segura do domínio

URL antiga conhecida:

```text
https://monitoramento-gb9g.onrender.com/api/agent/report
```

URL permanente:

```text
https://monitor.givovatransportes.com.br/api/agent/report
```

Regras do algoritmo:

1. Continuar respeitando a precedência: CLI > `SERVER_URL` > `agent_config.json` > padrão.
2. CLI e `SERVER_URL` são overrides explícitos e nunca são reescritos.
3. Se `agent_config.json.server_url`, após remover apenas espaços e barra final, for exatamente a URL Render conhecida, trocar pelo domínio permanente e persistir atomicamente (`arquivo.tmp`, flush, `os.replace`).
4. Se o arquivo não existir e o valor vier do padrão antigo, usar o novo padrão em memória.
5. Preservar toda URL customizada, inclusive outro Render, localhost de laboratório, Railway temporário ou URL com caminho diferente.
6. Não alterar token, device token, setor, nome, intervalos ou qualquer outra chave.
7. Se a gravação falhar, continuar com a configuração antiga e registrar erro sem conteúdo sensível.

Casos obrigatórios de teste:

- arquivo com URL Render exata migra e preserva todas as outras chaves;
- barra final na URL conhecida migra;
- URL customizada permanece byte a byte;
- CLI e `SERVER_URL` vencem e não alteram o arquivo;
- arquivo inválido não é destruído;
- segunda execução é idempotente;
- falha no `os.replace` mantém o original.

## Download direto do R2

O Agent 1.5.1 segue 302 automaticamente e valida o SHA-256 final. Para 1.5.2, endurecer o fluxo:

1. Consultar o endpoint autenticado do backend com `allow_redirects=False`.
2. Validar que o `Location` usa HTTPS e host R2/custom-domain aprovado.
3. Fazer o GET externo enviando somente `User-Agent`; nunca encaminhar `X-Agent-Token`, `X-Device-Token`, `Authorization` ou cookies.
4. Em 403 por URL expirada, solicitar uma nova URL ao backend e tentar uma única vez.
5. Em timeout, 404, hash divergente ou segunda falha, manter o executável atual e não iniciar o updater.
6. Somente mover o arquivo temporário depois de tamanho e SHA-256 conferidos.

## Gate de publicação

Antes de uma futura publicação: testes unitários, teste em PC canary, assinatura/antivírus, SHA-256 registrado, download R2 real, rollback do updater, 24h de observação e aprovação manual. Este plano não altera o canal stable nem cria release 1.5.2.
