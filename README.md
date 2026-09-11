# Sistema de Monitoramento de PCs — Givova Transportes

Sistema corporativo interno para telemetria, diagnóstico de hardware e monitoramento de integridade dos computadores operacionais e administrativos da **Givova Transportes**.

---

## 1. Sobre o Projeto

O sistema permite que o departamento de Tecnologia da Informação (TI) da Givova Transportes acompanhe em tempo real o status, a saúde e o consumo de recursos (processador, memória RAM, capacidade de disco e conectividade de rede) de todos os postos de trabalho e servidores internos da empresa, distribuídos por setores operacionais como Logística, Faturamento, Financeiro, Monitoramento, RH e Diretoria.

O objetivo é **monitoramento técnico contínuo** para prevenção de falhas e manutenção proativa, sem coleta de dados sensíveis ou violação da privacidade dos colaboradores.

---

## 2. Arquitetura

```
+-------------------------------------------------------------------------+
|                  COMPUTADORES CORPORATIVOS (CLIENTES)                   |
|  Script Agente (agente.py) coletando telemetria a cada 5 segundos:      |
|  - CPU %, RAM %, Disco %, Hardware, Sistema Operacional, Uptime         |
|  - Autenticação via Header: X-Agent-Token                               |
+-------------------------------------------------------------------------+
                                    │
                         HTTPS POST / JSON
                                    ▼
+-------------------------------------------------------------------------+
|                         SERVIDOR / API FLASK                            |
|  - Ingestão autenticada: /api/agent/report                              |
|  - Health check: /health                                                |
|  - Motor de Alertas (CPU > 90%, RAM > 90%, Disco > 90%, Offline)        |
|  - Autenticação Administrativa e Sessão Segura                          |
|  - Limpeza automática de histórico antigo (Retenção configurável)       |
+-------------------------------------------------------------------------+
                                    │
                                    ▼
+-------------------------------------------------------------------------+
|                     BANCO DE DADOS (SQLAlchemy)                         |
|  - SQLite (Ambiente Local / Testes / Deploy Simples)                    |
|  - PostgreSQL (Ambiente de Produção de Alta Escala)                     |
|  - Tabelas: Users, Devices, MetricsHistory, Alerts                      |
+-------------------------------------------------------------------------+
                                    │
                                    ▼
+-------------------------------------------------------------------------+
|                   DASHBOARD WEB (PAINEL DO OPERADOR TI)                 |
|  - Identidade Visual Givova: Branco, Laranja, Neutros de Alto Contraste |
|  - KPIs: Total de PCs, Online, Offline, Alertas, Médias de CPU/RAM      |
|  - Gráficos Interativos (Chart.js): Status, Setores, Histórico          |
|  - Tabela Corporativa: Busca em tempo real, Filtros por Setor e Status  |
|  - Modal de Detalhes: Gauges de hardware, especificações e histórico   |
+-------------------------------------------------------------------------+
```

---

## 3. Tecnologias Utilizadas

* **Backend / API**: Python 3.10+, Flask 3, Flask-SQLAlchemy, Werkzeug.
* **Servidor WSGI para Produção**: Waitress (Windows / Cross-platform) e Gunicorn (Linux / Containers).
* **Banco de Dados**: SQLite (padrão embutido) e PostgreSQL (compatível via SQLAlchemy).
* **Frontend Corporativo**: HTML5, TailwindCSS, Chart.js 4, JavaScript ES6 reativo.
* **Agente de Telemetria**: Python (`psutil`, `requests`, `socket`, `platform`).
* **Containerização & Deploy**: Docker, Docker Compose.

---

## 4. Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto baseado no `.env.example`:

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `FLASK_ENV` | `production` | Modo de execução (`development` ou `production`). |
| `SECRET_KEY` | *(obrigatório em prod)* | Chave de assinatura criptográfica de sessões web. |
| `AGENT_SECRET_TOKEN` | *(obrigatório)* | Chave mestra exigida pelo backend para autenticar os agentes. |
| `DATABASE_URL` | `sqlite:///monitoramento.db` | String de conexão SQLAlchemy (SQLite ou PostgreSQL). |
| `ADMIN_USERNAME` | `admin` | Nome do usuário administrador padrão criado no 1º boot. |
| `ADMIN_PASSWORD` | `GivovaAdmin@2026!` | Senha de acesso do administrador padrão. |
| `OFFLINE_THRESHOLD_SECONDS`| `30` | Segundos sem telemetria para marcar um PC como Offline. |
| `CPU_ALERT_PERCENT` | `90.0` | Porcentagem de processador para disparar alerta. |
| `RAM_ALERT_PERCENT` | `90.0` | Porcentagem de memória RAM para disparar alerta. |
| `DISK_ALERT_PERCENT` | `90.0` | Porcentagem de ocupação de disco para disparar alerta. |
| `METRICS_RETENTION_DAYS`| `7` | Prazo em dias para expurgo automático de métricas antigas. |
| `HOST` | `0.0.0.0` | Interface de rede para bind do servidor. |
| `PORT` | `5000` | Porta TCP do servidor web. |

---

## 5. Instalação e Execução em Desenvolvimento

### 5.1 Pré-requisitos
* Python 3.10 ou superior instalado.
* Git instalado.

### 5.2 Passo a Passo

1. **Clone o repositório:**
   ```bash
   git clone https://github.com/lucasgabri3l2010-bot/Monitoramento.git
   cd Monitoramento
   ```

2. **Crie e ative o ambiente virtual:**
   * **Windows (PowerShell):**
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```
   * **Linux / macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Instale as dependências:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Copie o arquivo de variáveis de ambiente:**
   ```bash
   cp .env.example .env
   ```

5. **Inicie o servidor:**
   ```bash
   python servidor.py
   ```
   *O banco SQLite e o usuário administrador serão gerados automaticamente na primeira inicialização.*

6. **Acesse o painel web:**
   Abra `http://localhost:5000` no seu navegador e efetue login com:
   * **Usuário:** `admin`
   * **Senha:** `admin` *(ou a senha configurada no seu `.env`)*

---

## 6. Executando os Testes Automatizados

Para rodar a suite completa de testes de integridade e segurança:

```bash
python -m unittest discover tests
```

---

## 7. Como Configurar o Agente nos Computadores

O script `agente.py` deve ser implantado nos computadores que serão monitorados.

### 7.1 Instalação no Terminal Cliente (Windows ou Linux)

1. Instale os módulos necessários:
   ```bash
   pip install psutil requests
   ```

2. Crie o arquivo `agent_config.json` no mesmo diretório do `agente.py`:
   ```json
   {
       "server_url": "http://IP_DO_SERVIDOR:5000/api/agent/report",
       "agent_token": "givova_agent_token_dev_2026",
       "department": "Logística",
       "display_name": "PC Expedição 01",
       "interval_seconds": 5
   }
   ```
   *(Substitua `IP_DO_SERVIDOR` pelo IP local ou domínio público do seu servidor e o `agent_token` pelo mesmo valor configurado no `.env` do servidor).*

3. Execute o agente:
   ```bash
   python agente.py
   ```

### 7.2 Execução como Tarefa de Inicialização no Windows
Para iniciar o agente em segundo plano silenciosamente junto ao Windows:
1. Abra o **Agendador de Tarefas** (`taskschd.msc`).
2. Crie uma Tarefa Básica:
   * **Disparador:** Ao inicializar o sistema / Ao fazer logon.
   * **Ação:** Iniciar um programa -> Programa: `pythonw.exe` -> Argumentos: `agente.py` -> Iniciar em: pasta do script.

---

## 8. Monitoramento de Atividade Atual

O sistema inclui detecção leve de aplicativo em primeiro plano e, opcionalmente, o domínio do site ativo no navegador (Google Chrome e Microsoft Edge).

### 8.1 O que é coletado:
* **Nome do aplicativo em foco** (ex: `Microsoft Excel`, `VS Code`, `Outlook`, `Google Chrome`).
* **Domínio raiz do site ativo** (ex: `chatgpt.com`, `youtube.com`, `givovatransportes.com.br`).
* **Horário da última alteração**.

### 8.2 O que NÃO é coletado (Compromisso Estrito de Privacidade):
* ❌ **Sem URLs completas**: Caminhos como `/busca?q=teste` ou `/painel/123` são descartados no navegador antes de qualquer envio.
* ❌ **Sem histórico de navegação**: Não há gravação de logs históricos de navegação nem cronologia de páginas.
* ❌ **Sem formulários, senhas ou conteúdo**: Nenhum texto digitado ou elemento da página é lido.
* ❌ **Sem screenshots ou keylogger**.
* ❌ **Sem monitoramento anônimo**: Abas InPrivate ou Anônimas são 100% ignoradas.

### 8.3 Como Habilitar ou Desabilitar:
* **No Servidor / Backend**: Configure a variável `ACTIVITY_MONITORING_ENABLED=true` ou `false` no `.env`.
* **No Agente**:
  * No arquivo `agent_config.json`: `"activity_monitoring": true` (ou `false`).
  * Ou execute o agente com a flag: `python agente.py --sem-atividade`.

### 8.4 Instalação da Extensão Corporativa Chromium (Chrome e Edge):
A extensão complementar envia apenas o hostname da aba ativa diretamente para o agente local (`http://127.0.0.1:5005/active-tab`), sem passar por servidores externos:
1. Abra `chrome://extensions` (no Chrome) ou `edge://extensions` (no Edge).
2. Ative a chave **Modo do Desenvolvedor** no topo.
3. Clique em **Carregar sem compactação** (ou *Carregar descompactada*).
4. Selecione a pasta `extension/` deste projeto.
5. Pronto! O domínio ativo passará a ser transmitido ao agente e refletido no dashboard.

*Observação: Caso a extensão não esteja instalada ou o usuário utilize outro software, o sistema continuará operando normalmente exibindo apenas o nome do aplicativo (ex: `Google Chrome` ou `Microsoft Excel`).*

---

## 9. Guia de Deploy em Produção

### 8.1 Opção A: Deploy via Docker / Docker Compose

O repositório já inclui `Dockerfile` e `docker-compose.yml` otimizados para produção:

```bash
# Sobe o container em background com reinicialização automática
docker compose up -d --build
```

### 8.2 Opção B: Deploy em Plataformas de Nuvem (Render / Railway / Fly.io)

1. Conecte seu repositório Git na plataforma.
2. Defina o tipo de serviço como **Web Service (Python)** ou **Docker**.
3. Comando de Inicialização (se não usar Docker):
   ```bash
   pip install -r requirements.txt && gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 servidor:app
   ```
4. Adicione as Variáveis de Ambiente no painel da nuvem (veja a seção 4).
5. Configure o endpoint de checagem de integridade (**Health Check Path**): `/health`.

### 8.3 Opção C: Deploy em Servidor Windows Local (IIS / Waitress)

Para executar como serviço no Windows:
```bash
python wsgi.py
```
O servidor será servido através do motor WSGI de alto desempenho **Waitress**.

---

## 9. Segurança e Privacidade

* **Isolamento de Credenciais**: Senhas de operadores são armazenadas com hash criptográfico (`scrypt`/Werkzeug).
* **Autenticação do Agente**: Todas as chamadas ao endpoint de telemetria exigem validação criptográfica do cabeçalho `X-Agent-Token`. Tentativas sem autorização são imediatamente bloqueadas com código HTTP `401 Unauthorized`.
* **Proteção contra Spoofing**: Cada equipamento gera um identificador único de hardware (`uuid`) que impede duplicação ou sobrescrita maliciosa.
* **Privacidade Absoluta**: O agente coleta apenas dados técnicos de hardware e rede (CPU, RAM, Disco, IP e Uptime). Não são executados keyloggers, leitura de telas ou captura de arquivos pessoais.
