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
   * **Senha:** `GivovaAdmin@2026!` *(ou a senha configurada no seu `.env`)*

---

## 6. Executando os Testes Automatizados

Para rodar a suite completa de testes de integridade e segurança (6 testes):

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

2. Crie o arquivo `agent_config.json` no mesmo diretório do `agente.py` (ou copie a partir de `agent_config.example.json`):
   ```json
   {
       "server_url": "https://seu-servico.onrender.com/api/agent/report",
       "agent_token": "SEU_TOKEN_SECRETO_DO_RENDER",
       "department": "Operacional",
       "display_name": "PC-EXPEDICAO-01",
       "interval_seconds": 5,
       "timeout_seconds": 10,
       "activity_monitoring": true
   }
   ```

3. Execute o agente:
   ```bash
   python agente.py
   ```

---

## 8. Monitoramento de Atividade Atual (Janela e Domínio)

### 8.1 Funcionalidade Corporativa
Exibe no painel qual aplicativo está atualmente em foco (ex: `Microsoft Excel`, `VS Code`, `Google Chrome`) e, quando for um navegador corporativo com a extensão habilitada, mostra o domínio visitado (ex: `givovatransportes.com.br`).

### 8.2 Privacidade e Segurança Garantidas por Design:
* ❌ **Sem histórico de navegação**: Apenas o domínio ativo atual.
* ❌ **Sem captura de URLs completas ou parâmetros**: Parâmetros, paths e queries são descartados.
* ❌ **Sem captura de conteúdo ou digitação**: Não há leitura de telas nem keylogger.
* ❌ **Sem monitoramento anônimo**: Abas InPrivate ou Anônimas são 100% ignoradas.

### 8.3 Como Habilitar ou Desabilitar:
* **No Servidor / Backend**: Configure `ACTIVITY_MONITORING_ENABLED=true` ou `false`.
* **No Agente**:
  * No arquivo `agent_config.json`: `"activity_monitoring": true` (ou `false`).
  * Ou execute o agente com a flag: `python agente.py --sem-atividade`.

### 8.4 Instalação da Extensão Corporativa Chromium (Chrome e Edge):
A extensão envia apenas o hostname da aba ativa diretamente para o agente local (`http://127.0.0.1:5005/active-tab`), sem passar por servidores externos:
1. Abra `chrome://extensions` (Chrome) ou `edge://extensions` (Edge).
2. Ative o **Modo do Desenvolvedor**.
3. Clique em **Carregar sem compactação** (ou *Carregar descompactada*).
4. Selecione a pasta `extension/` deste projeto.
5. Pronto! O domínio ativo é transmitido localmente ao agente e enviado de forma segura ao servidor.

---

## 9. Deploy Rápido — Render + Neon (PostgreSQL)

Guia completo passo a passo para colocar a aplicação online para a apresentação à diretoria.

### Passo 1: Criar o Banco PostgreSQL no Neon
1. Acesse [neon.tech](https://neon.tech) e crie uma conta gratuita (ou faça login com GitHub).
2. Crie um novo projeto, por exemplo `givova-monitoramento`.
3. No painel do projeto, em **Connection Details**, selecione a conexão padrão e copie a **Connection String**.
   * Exemplo gerado pelo Neon:
     `postgresql://usuario:senha@ep-xyz-123456.us-east-2.aws.neon.tech/neondb?sslmode=require`
4. Guarde essa URL para o próximo passo.

### Passo 2: Criar o Web Service no Render
1. Acesse [render.com](https://render.com) e crie ou acesse sua conta.
2. Clique em **New +** > **Web Service**.
3. Conecte o repositório do GitHub `lucasgabri3l2010-bot/Monitoramento`.
4. Preencha as configurações do serviço:
   * **Name:** `givova-monitoramento` (ou o nome desejado)
   * **Region:** Ohio (US East) ou Oregon (US West)
   * **Branch:** `main`
   * **Runtime:** `Python 3` (ou escolha `Docker`, ambos funcionam nativamente)
   * **Build Command:** `pip install -r requirements.txt`
   * **Start Command:** `gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 servidor:app`
   * **Plan:** `Free`
5. Em **Advanced**, configure:
   * **Health Check Path:** `/health`
6. Em **Environment Variables**, adicione a lista de variáveis abaixo.

### Passo 3: Tabela Exata de Variáveis de Ambiente no Render

| Variável | Valor Recomendado / Como Obter | Obrigatória? |
| :--- | :--- | :--- |
| `FLASK_ENV` | `production` | Sim |
| `SECRET_KEY` | *(Gere uma chave segura, ex: `python -c "import secrets; print(secrets.token_hex(32))"`)* | Sim |
| `AGENT_SECRET_TOKEN` | *(Gere um token seguro, ex: `python -c "import secrets; print(secrets.token_hex(24))"`)* | Sim |
| `DATABASE_URL` | *(Cole a Connection String obtida no Neon)* | Sim |
| `ADMIN_USERNAME` | `admin` *(ou o usuário que preferir)* | Sim |
| `ADMIN_PASSWORD` | `SuaSenhaForte@2026!` *(defina uma senha segura para seu login)* | Sim |
| `OFFLINE_THRESHOLD_SECONDS` | `30` | Não (padrão: 30) |
| `CPU_ALERT_PERCENT` | `90.0` | Não (padrão: 90.0) |
| `RAM_ALERT_PERCENT` | `90.0` | Não (padrão: 90.0) |
| `DISK_ALERT_PERCENT` | `90.0` | Não (padrão: 90.0) |
| `METRICS_RETENTION_DAYS` | `7` | Não (padrão: 7) |
| `ACTIVITY_MONITORING_ENABLED`| `true` | Não (padrão: true) |
| `SESSION_COOKIE_SECURE` | `true` | Não (padrão: true em prod) |

> 💡 **Dica de Deploy com `render.yaml` (Blueprint):** Se preferir, no Render clique em **New +** > **Blueprint** e conecte o repositório. O Render lerá o arquivo `render.yaml` automaticamente, preenchendo as configurações e solicitando apenas o preenchimento de `DATABASE_URL` e `ADMIN_PASSWORD`!

### Passo 4: URL Gerada e Health Check
Assim que o deploy for concluído, o Render disponibilizará sua URL pública HTTPS:
* Exemplo: `https://givova-monitoramento.onrender.com`
* Teste a saúde acessando: `https://givova-monitoramento.onrender.com/health`
* Resposta esperada: `{"status": "ok", "database": "connected", ...}` com status HTTP 200.

### Passo 5: Configurar e Executar o Agente Local
No computador a ser monitorado (ou no seu computador de teste):
1. Crie ou edite o arquivo `agent_config.json`:
   ```json
   {
       "server_url": "https://givova-monitoramento.onrender.com/api/agent/report",
       "agent_token": "COPIE_O_AGENT_SECRET_TOKEN_DO_RENDER",
       "department": "TI",
       "display_name": "Estação de Trabalho (Apresentação)",
       "interval_seconds": 5
   }
   ```
   *(Nota: O agente aceita tanto `https://givova-monitoramento.onrender.com` quanto `https://givova-monitoramento.onrender.com/api/agent/report`).*

2. Inicie o agente:
   ```powershell
   python agente.py
   ```
3. O agente exibirá:
   ```
   [OK] [HOSTNAME] CPU: 12.5% | RAM: 48.0% | Disco: 35.0% - Enviado com sucesso (HTTP 200)
   ```

---

## 10. Roteiro de Demonstração para a Diretoria (10 Passos)

1. **Apresentação Inicial e Acesso Seguro**:
   Acesse a URL do Render no navegador. Mostre a tela de login corporativa com identidade visual da Givova Transportes.
2. **Login Administrativo**:
   Entre com seu usuário e senha. Mostre a transição suave para o Dashboard principal.
3. **Visão Geral dos KPIs**:
   Apresente os cards superiores com total de computadores monitorados, status online, alertas ativos e médias de consumo de hardware.
4. **Telemetria em Tempo Real**:
   Mostre o card da máquina conectada e destaque como os indicadores atualizam automaticamente sem necessidade de recarregar a página (F5).
5. **Demonstração da Atividade Atual (Diferencial Executivo)**:
   Abra uma planilha no Excel ou abra o navegador no site da Givova Transportes. Mostre no dashboard o rótulo atualizando em tempo real com o aplicativo/site em primeiro plano.
6. **Gráficos e Diagnóstico Histórico**:
   Clique sobre a máquina para abrir os detalhes completos: histórico de CPU e RAM, especificações detalhadas do processador, núcleos, memória física e disco.
7. **Simulação de Sobrecarga / Resiliência**:
   Mostre a coluna de alertas e explique a detecção automática de gargalos (processador >90%, memória cheia ou falhas de conexão).
8. **Edição Rápida e Governança**:
   Altere o setor ou apelido da máquina pelo painel (ex: mude de "TI" para "Diretoria" ou "Logística") e mostre o agrupamento automático.
9. **Detecção Automática de Máquina Desconectada**:
   Pause o agente local por mais de 30 segundos. Mostre o status transicionando automaticamente para **Offline** com badge visual informativo.
10. **Conclusão Técnica**:
    Ressalte a arquitetura escalável: backend em nuvem no Render, banco de dados gerenciado no Neon, agentes ultraleves rodando em segundo plano sem impacto no desempenho dos usuários e conformidade estrita de privacidade (sem keylogger, sem espionagem indevida).
