# Extensão Corporativa — Monitor de Aba Ativa (Givova Transportes)

Extensão Manifest V3 ultraleve para **Google Chrome** e **Microsoft Edge** que informa ao agente de monitoramento local qual domínio web está em primeiro plano na máquina.

---

## 🔒 Compromisso de Privacidade e Segurança
* **O que a extensão faz:** Identifica apenas o domínio raiz (ex: `chatgpt.com`, `youtube.com`, `givovatransportes.com.br`) da aba ativa.
* **O que a extensão NÃO faz:**
  * ❌ NÃO coleta paths (`/search`, `/dashboard/123`, etc.).
  * ❌ NÃO coleta parâmetros de URL nem termos pesquisados.
  * ❌ NÃO captura histórico de navegação.
  * ❌ NÃO lê conteúdo da página, formulários, cookies ou senhas.
  * ❌ NÃO captura abas em Modo Anônimo / InPrivate.
  * ❌ NÃO se comunica com a Internet externa: envia dados exclusivamente via `http://127.0.0.1:5005` (localhost).

---

## 🚀 Como Instalar no Google Chrome ou Microsoft Edge

### 1. No Google Chrome:
1. Abra o navegador e digite na barra de endereços: `chrome://extensions`
2. Ative a chave **Modo do desenvolvedor** no canto superior direito.
3. Clique no botão **Carregar sem compactação** (Load unpacked).
4. Selecione a pasta `extension/` deste projeto.
5. Pronto! A extensão estará ativa e comunicando com o agente local.

### 2. No Microsoft Edge:
1. Abra o navegador e digite na barra de endereços: `edge://extensions`
2. Ative a chave **Modo do desenvolvedor** na barra lateral esquerda.
3. Clique em **Carregar descompactada** (Load unpacked).
4. Selecione a pasta `extension/` deste projeto.
5. Pronto!
