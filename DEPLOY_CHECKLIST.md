# Checklist de Deploy em Produção — Givova Transportes

Utilize esta checklist para homologação e publicação do **Sistema de Monitoramento de PCs**.

---

## 1. Infraestrutura & Servidor (Backend)
- [ ] **Ambiente de Hospedagem Definido**: Render, Railway, Fly.io, VPS Linux ou Servidor Windows Corporativo.
- [ ] **Variáveis de Ambiente Criadas no Servidor**:
  - [ ] `FLASK_ENV=production`
  - [ ] `SECRET_KEY` configurada com hash seguro e aleatório de 64 caracteres.
  - [ ] `AGENT_SECRET_TOKEN` configurado com chave forte compartilhada apenas com os agentes autorizados.
  - [ ] `DATABASE_URL` apontando para o banco de produção (SQLite persistente ou PostgreSQL).
  - [ ] `ADMIN_USERNAME` e `ADMIN_PASSWORD` fortes definidos para o primeiro acesso.
  - [ ] `OFFLINE_THRESHOLD_SECONDS=30` (ou ajustado conforme política interna).
  - [ ] `CPU_ALERT_PERCENT=90.0`, `RAM_ALERT_PERCENT=90.0`, `DISK_ALERT_PERCENT=90.0`.
  - [ ] `METRICS_RETENTION_DAYS=7` (ou retenção estendida conforme capacidade).
  - [ ] `ACTIVITY_MONITORING_ENABLED=true` (ou `false` se a empresa optar por não coletar aplicativos ativos).
- [ ] **Porta e Bind**: Garantir bind em `0.0.0.0:${PORT}` (já configurado no `Dockerfile` e `wsgi.py`).
- [ ] **Health Check Testado**: Validar resposta `200 OK` na rota pública `GET https://seu-dominio.com/health`.
- [ ] **Certificado SSL/HTTPS Ativo**: Tráfego criptografado para garantir segurança de tokens e telemetria.

---

## 2. Banco de Dados
- [ ] Banco inicializado e tabelas criadas automaticamente na primeira subida (`users`, `devices`, `metrics_history`, `alerts`).
- [ ] Volume persistente montado caso utilize SQLite em container Docker (`/app/instance`).
- [ ] Backup automático configurado caso utilize PostgreSQL em nuvem (Render PostgreSQL, Supabase, Neon).

---

## 3. Painel Administrativo Web
- [ ] Acesso à tela de `/login` validado.
- [ ] Login com credenciais do administrador realizado com sucesso.
- [ ] Redirecionamento correto para o `/` (Dashboard).
- [ ] Bloqueio de acesso a rotas anônimas testado (redireciona para `/login`).
- [ ] Logout testado com limpeza de sessão.
- [ ] Gráficos do Chart.js carregando sem erros no console (F12).

---

## 4. Agentes de Monitoramento (Computadores Físicos)
- [ ] Python 3.8+ instalado nos computadores da empresa.
- [ ] Pacotes instalados: `pip install psutil requests`.
- [ ] Arquivo `agent_config.json` configurado na máquina do usuário:
  - [ ] `server_url` apontando para a URL pública/interna de produção (`https://seu-dominio.com/api/agent/report`).
  - [ ] `agent_token` idêntico ao `AGENT_SECRET_TOKEN` do servidor.
  - [ ] `department` configurado corretamente (ex: `Logística`, `TI`, `Faturamento`, `Financeiro`, etc.).
  - [ ] `display_name` definido para identificação amigável do posto de trabalho.
- [ ] Execução inicial do `agente.py` validada com log de sucesso `OK [HOSTNAME] - Enviado com sucesso (HTTP 200)`.
- [ ] Script configurado para inicialização automática no boot (Task Scheduler no Windows ou systemd no Linux).
- [ ] *(Opcional)* Extensão corporativa Chromium carregada em `chrome://extensions` ou `edge://extensions` nas máquinas que necessitam de telemetria de domínios web.

---

## 5. Validação Operacional Final
- [ ] Máquina aparece no Dashboard com status **Online** (badge verde).
- [ ] Telemetria de CPU, RAM e Disco refletindo dados reais do computador.
- [ ] Gráfico de histórico individual acumulando métricas a cada ciclo de envio.
- [ ] Teste de alerta: sobrecarga simulada ou desconexão por mais de 30s gera status **Offline** / **Alerta**.
- [ ] Edição de setor e nome do computador via painel web testada com sucesso.
- [ ] Log do servidor limpo, sem erros de unhandled exception ou vazamento de senhas/tokens.
