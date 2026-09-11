// =================================================================
// Givova Transportes - Monitor de Aba Ativa (Manifest V3)
// Finalidade: Extrair estritamente o hostname da aba ativa
// PRIVACIDADE GARANTIDA:
// - NÃO armazena histórico
// - NÃO lê conteúdo da página nem formulários
// - DESCARTA imediatamente caminhos (path), query strings e hashes
// - IGNORA navegação anônima / privada
// =================================================================

const AGENT_ENDPOINT = "http://127.0.0.1:5005/active-tab";
let lastReportedDomain = null;

async function reportActiveTab(tabId) {
  try {
    if (!tabId) return;
    const tab = await chrome.tabs.get(tabId);
    if (!tab || !tab.active) return;

    // PRIVACIDADE: Abas anônimas/privadas são 100% ignoradas
    if (tab.incognito) {
      return;
    }

    if (!tab.url) return;

    // Filtra apenas URLs HTTP e HTTPS válidas (ignora chrome://, edge://, file://, etc.)
    const url = new URL(tab.url);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return;
    }

    // Extrai unicamente o domínio/hostname, removendo 'www.' para apresentação padronizada
    const domain = url.hostname.replace(/^www\./, "").toLowerCase();

    // Evita requisições redundantes se o domínio já foi reportado
    if (domain === lastReportedDomain) {
      return;
    }

    lastReportedDomain = domain;

    const isEdge = navigator.userAgent.includes("Edg/");
    const browserName = isEdge ? "Microsoft Edge" : "Google Chrome";

    // Envia unicamente ao agente local da máquina (127.0.0.1)
    await fetch(AGENT_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        domain: domain,
        browser: browserName,
        timestamp: Date.now()
      })
    }).catch(() => {
      // Falha silenciosa quando o agente local estiver desligado
    });

  } catch (err) {
    // Tratamento de exceções resiliente
  }
}

// 1. Disparado ao alternar entre abas
chrome.tabs.onActivated.addListener((activeInfo) => {
  reportActiveTab(activeInfo.tabId);
});

// 2. Disparado quando a aba ativa navega ou conclui carregamento
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (tab.active && (changeInfo.status === "complete" || changeInfo.url)) {
    reportActiveTab(tabId);
  }
});

// 3. Disparado quando o foco da janela muda
chrome.windows.onFocusChanged.addListener(async (windowId) => {
  if (windowId === chrome.windows.WINDOW_ID_NONE) return;
  try {
    const tabs = await chrome.tabs.query({ active: true, windowId: windowId });
    if (tabs && tabs.length > 0 && tabs[0].id) {
      lastReportedDomain = null; // Reseta para reenviar ao retomar o foco
      reportActiveTab(tabs[0].id);
    }
  } catch (e) {}
});
