# Arquitetura de Auto-Update do Agente — Givova Monitor

O **Givova Monitor Agent** possui um mecanismo de atualização automática remota (Instalar uma vez -> Atualizar para sempre) projetado especificamente para frotas corporativas em ambiente Windows.

A arquitetura garante que novas versões possam ser distribuídas e aplicadas sem necessidade de acesso físico aos computadores dos colaboradores, mantendo **100% de tolerância a falhas** com rollback automático imediato em caso de problemas.

---

## 1. Visão Geral do Ciclo de Vida do Auto-Update

`
+-------------------------------------------------------------------------------+
| 1. SERVIDOR (Render + Neon PostgreSQL)                                        |
|    - Publicação de release via painel ou API (/api/admin/releases/publish)   |
|    - Armazenamento persistente na tabela agent_releases (binário BYTEA/URL)   |
|    - Manifesto com versão semântica (SemVer), SHA-256 e release notes         |
+-------------------------------------------------------------------------------+
                                      │
                         /api/agent/update (HTTPS)
                                      ▼
+-------------------------------------------------------------------------------+
| 2. AGENTE EM EXECUÇÃO (GivovaMonitorAgent.exe - v1.3.0)                       |
|    - Worker em background checa atualizações periodicamente (com jitter)      |
|    - Validação SemVer: detecta se target_version > current_version            |
|    - Verificação contra failed_updates.json (evita repetição de falhas)       |
|    - Download seguro do binário v1.4.0 para temp\update_v1.4.0.exe            |
|    - Validação criptográfica de integridade SHA-256                           |
|    - Gera update_id único e salva pending_update.json                         |
|    - Invoca GivovaMonitorUpdater.exe e encerra a si mesmo                     |
+-------------------------------------------------------------------------------+
                                      │
                     Processo Desanexado (Detach)
                                      ▼
+-------------------------------------------------------------------------------+
| 3. SUPERVISOR DE ATUALIZAÇÃO (GivovaMonitorUpdater.exe)                       |
|    - Aguarda liberação do PID anterior e mutex de execução                    |
|    - Limpa confirmações antigas residuais                                     |
|    - Cria backup seguro: GivovaMonitorAgent.previous.exe                     |
|    - Substitui atomicamente GivovaMonitorAgent.exe pelo novo executável       |
|    - Inicia o novo agente via Task Scheduler ou processo nativo               |
|    - Monitora confirmação de saúde ativa (timeout padrão: 45 segundos)        |
+-------------------------------------------------------------------------------+
                  │                                            │
           (Sucesso: 200 OK)                          (Timeout / Falha)
                  ▼                                            ▼
+------------------------------------+       +------------------------------------+
| 4A. ATUALIZAÇÃO BEM-SUCEDIDA       |       | 4B. ROLLBACK AUTOMÁTICO CRÍTICO    |
| - Novo agente envia métricas       |       | - Restaura versão .previous.exe    |
| - Emite update_confirmed.json      |       | - Registra em failed_updates.json  |
|   com update_id correspondente     |       | - Reinicia o agente anterior       |
| - Supervisor limpa arquivos temp   |       | - Preserva configuração local      |
| - Frota atualizada no Dashboard    |       | - Zero intervenção humana          |
+------------------------------------+       +------------------------------------+
`

---

## 2. Componentes e Responsabilidades

### 2.1 Agente (agente.py / GivovaMonitorAgent.exe)
* **Thread de Verificação Periódica**: Executa a cada 6 horas (configurável via update_check_interval) com jitter aleatório de +-10 minutos para evitar picos de tráfego simultâneos no servidor Render.
* **Consulta de Versão**: Chama GET /api/agent/update enviando sua versão atual, UUID e token de autenticação.
* **Validação Criptográfica**: Ao receber o executável da nova versão, calcula seu hash SHA-256 e compara estritamente com o hash homologado pelo servidor. Se houver divergência, o arquivo é descartado imediatamente.
* **Marcador de Saúde Unívoco (update_id)**:
  - Antes de invocar o atualizador, gera um identificador único, ex: upd-7f9a2b41c0e3.
  - Grava pending_update.json localmente e passa --update-id upd-7f9a2b41c0e3 para o updater.
  - Ao iniciar com sucesso e completar a primeira transmissão de métricas ao servidor, o novo agente lê pending_update.json, emite update_confirmed.json com o mesmo update_id e apaga pending_update.json.

### 2.2 Supervisor de Atualização (updater.py / GivovaMonitorUpdater.exe)
* Executável independente que opera como supervisor de processo temporário.
* **Isolamento de Erros**: Se a nova versão apresentar problemas de inicialização (ex: incompatibilidade de DLL, crash em runtime, rejeição de autenticação), o supervisor detecta o timeout (45 segundos) sem confirmação de saúde e inicia o rollback.
* **Rollback Seguro**:
  1. Encerra qualquer processo em loop do novo agente via 	askkill /F.
  2. Restaura GivovaMonitorAgent.previous.exe como GivovaMonitorAgent.exe.
  3. Adiciona a versão com falha no arquivo ailed_updates.json.
  4. Reinicia a versão estável através do Agendador de Tarefas do Windows (schtasks /run /tn Givova Monitor Agent).
* **Proteção Contra Loop de Rollback**: Uma versão presente em ailed_updates.json jamais é baixada novamente pelo agente até que uma nova versão superior seja publicada.

---

## 3. Estratégia de Armazenamento de Releases no Render

O Render opera com sistema de arquivos efêmero: quando um deploy ocorre ou o container reinicia, arquivos gravados em disco são descartados.

Para contornar essa restrição sem exigir provedores externos pagos no MVP, o sistema adota **duas estratégias complementares**:

### Estratégia A: Armazenamento Nativo no PostgreSQL Neon (Padrão)
* O modelo AgentRelease persiste o binário compilado .exe em uma coluna BYTEA (LargeBinary) no PostgreSQL.
* Ao publicar uma release via /api/admin/releases/publish, o upload do arquivo binário é salvo diretamente no banco de dados e sobrevive a qualquer recriação ou restart dos containers do Render.
* O endpoint de download (GET /api/agent/download/<version>) lê o binário do PostgreSQL e entrega o stream via io.BytesIO com cabeçalho pplication/octet-stream.

### Estratégia B: Redirecionamento para GitHub Releases ou S3 / Cloudflare R2
* O modelo AgentRelease e o formulário administrativo aceitam um campo download_url externo.
* Exemplo: https://github.com/lucasgabri3l2010-bot/Monitoramento/releases/download/v1.4.0/GivovaMonitorAgent.exe.
* O servidor valida a autenticação corporativa do agente (X-Agent-Token) e responde com redirecionamento HTTP 302 para a URL externa segura.

---

## 4. Como Publicar uma Nova Release do Agente

### Método 1: Via Script PowerShell Automatizado (Recomendado para TI)
Na máquina de desenvolvimento da TI com Windows e PowerShell:

`powershell
# 1. Compila os executáveis do agente e do atualizador
powershell -ExecutionPolicy Bypass -File .\scripts\Build-GivovaMonitor.ps1

# 2. Publica a release no servidor com validação SHA-256
powershell -ExecutionPolicy Bypass -File .\scripts\Publish-AgentRelease.ps1 -Version 1.4.0 -ServerUrl https://monitoramento-gb9g.onrender.com -Notes Atualização de estabilidade e novas políticas de segurança
`

O script:
* Valida o formato SemVer (1.4.0);
* Calcula o hash SHA-256 do binário GivovaMonitorAgent.exe;
* Gera a pasta local eleases\1.4.0\;
* Envia o manifesto e o binário para POST /api/admin/releases/publish autenticado;
* Atualiza a versão global no banco para consulta imediata de toda a frota.

### Método 2: Via Painel Web do Dashboard
1. Acesse o Dashboard em https://monitoramento-gb9g.onrender.com.
2. Acesse a aba **Configurações** > **Gestão de Versões e Auto-Update**.
3. Selecione a versão, preencha o changelog, anexe o novo GivovaMonitorAgent.exe e clique em **Publicar Release**.
