# Políticas de Uso Corporativo & Alertas de Segurança — Givova Monitor

O módulo de **Políticas Corporativas de Uso** permite à equipe de Tecnologia da Informação (TI) da Givova Transportes estabelecer regras de governança para o uso de sites e aplicativos nos computadores da frota.

O sistema foi concebido sob o princípio de **Privacy by Design**: identifica violações corporativas graves (apostas em horário de trabalho, jogos, torrents, downloads não autorizados) **sem devassar a privacidade do colaborador** (sem captura de telas, sem keyloggers, sem armazenamento de pesquisas pessoais e sem coleta de parâmetros/URLs completos).

---

## 1. Tipos de Regras e Categorias

### Tipos de Regras (ule_type)
* **Domínio (domain)**: Monitora o hostname de sites visitados no navegador em primeiro plano (ex: et365.com, 
etflix.com, 	iktok.com).
* **Aplicativo (pplication)**: Monitora o nome do executável em primeiro plano (ex: steam.exe, utorrent.exe, alorant.exe).

### Categorias Oficiais
* Apostas (ex: Bet365, Betano, Stake, Blaze)
* Jogos (ex: Steam, Valorant, Roblox, Epic Games)
* Streaming (ex: Netflix, Prime Video, Disney+)
* Redes Sociais (ex: TikTok, Instagram, Twitter/X)
* Adulto
* Malware & Phishing
* Aplicativo Não Autorizado
* Outro

### Níveis de Severidade (severity)
* critical: Alerta visual vermelho no dashboard e notificação prioritária imediata no Windows Toast para os computadores da TI.
* warning: Alerta visual âmbar no dashboard para acompanhamento preventivo.
* info: Registro informativo de auditoria.

### Escopos de Aplicação (scope_type)
* global: Aplica a regra a **todos os computadores da frota**.
* department: Aplica a regra apenas aos computadores de um setor específico (ex: Logística, Faturamento, Operacional).
* device: Aplica a regra a um único computador especificado por hostname ou UUID.

---

## 2. Normalização Canônica de Domínios e Proteção Contra Falsos Positivos

Para garantir precisão e evitar contorno de regras ou falsos alarmes, o sistema implementa a função 
ormalize_domain() e match_domain_secure():

1. **Higienização Completa**:
   - Converte para minúsculas (et365.com);
   - Remove protocolos (https://, http://);
   - Remove portas (:443, :8080);
   - Remove paths e query strings (/sports?ref=123 -> descartado);
   - Remove prefixo www. e pontos finais residuais.

2. **Matching Canônico e Subdomínios**:
   - Uma regra para et365.com intercepta com segurança:
     - et365.com
     - m.bet365.com
     - sports.bet365.com
     - cassino.bet365.com

3. **Proteção Contra Falsos Positivos de Substring**:
   - 
otbet365.com **NÃO** dispara a regra de et365.com.
   - akebet365.com **NÃO** dispara a regra de et365.com.
   - et365.corporate.net **NÃO** dispara a regra de et365.com.

---

## 3. Ciclo de Vida do Evento e Deduplicação Inteligente

Para evitar que uma máquina navegando em um site por 15 minutos gere 180 alertas repetidos na base (a cada 5s de envio), o sistema implementa **Deduplicação com Acúmulo de Duração**:

`
[Início do Acesso]
  │  Usuário acessa bet365.com às 14:00:00
  ▼
[Criação da Ocorrência]
  │  PolicyEvent criado com status='active', first_seen=14:00:00, duration_seconds=0
  ▼
[Próximos Reports (14:00:05, 14:00:10...)]
  │  Ocorrência ativa localizada para o mesmo computador e domínio
  │  last_seen atualizado para 14:00:10
  │  duration_seconds acumulado (ex: 10s)
  ▼
[Usuário Retorna ao Trabalho (14:05:00)]
  │  Usuário fecha a aba e volta para givovatransportes.com.br ou Excel
  ▼
[Fechamento Automático da Ocorrência]
  │  Sistema detecta que a atividade atual é lícita
  │  Evento anterior marcado com status='closed', resolved_at=14:05:00
  │  Duração consolidada: 5m 00s registrada no histórico
`

---

## 4. Cache em Memória com Sincronização Multi-Worker (Gunicorn)

Em produção no Render, o servidor executa com múltiplos workers e threads do Gunicorn (--workers 2 --threads 4).

Para aliar **altíssima performance** (sem queries ao banco a cada 5s para cada computador da frota) e **sincronização perfeita**:

1. Cada worker mantém um cache local em memória (CachedPolicyRule), livre de DetachedInstanceError.
2. A tabela system_metadata armazena a versão global das regras (policy_rules_version).
3. A cada 5 segundos (TTL configurável), os workers verificam se policy_rules_version foi alterado.
4. Qualquer operação de CRUD ou toggle de regra atualiza policy_rules_version no banco instantaneamente.
5. Todos os workers recarregam suas regras na próxima checagem, sem necessidade de servidores Redis dedicados.

---

## 5. Dispositivos Autorizados da TI & Notificações Windows Toast

A equipe de suporte e segurança da informação pode receber alertas em tempo real na própria área de trabalho:

1. No Dashboard, clique em **Editar** no computador do técnico de TI e marque:
   [x] Terminal Autorizado de TI (Admin Device)
2. O servidor gera um device_token criptográfico exclusivo para a máquina.
3. No gent_config.json da máquina da TI, ative:
   admin_notifications: true
4. O worker de background do agente consulta GET /api/agent/admin-alerts autenticado.
5. Se qualquer computador da empresa violar uma política de severidade critical ou warning, uma notificação nativa **Windows Toast** é exibida discretamente no canto da tela do técnico de TI com o setor e o computador infrator.

---

## 6. Garantias Estritas de Privacidade (LGPD & Compliance)

* 🛡️ **Zero Registro de Senhas ou Digitação**: O agente não instala keyloggers nem monitora eventos de teclado ou mouse.
* 🛡️ **Zero Captura de Telas**: Nenhuma imagem ou gravação de tela é realizada.
* 🛡️ **Privacidade de Parâmetros Web**: Apenas o nome do domínio principal é avaliado. Códigos de rastreamento, consultas do Google, parâmetros de busca ou números de documentos jamais são transmitidos ou armazenados.
* 🛡️ **Modo Anônimo**: Abas anônimas são ignoradas pela extensão corporativa.
