# Guia de Implantação Corporativa da Extensão — Chrome & Edge

Este documento detalha os procedimentos oficiais e homologados para implantação administrativa da **Extensão Corporativa do Givova Monitor** em ambientes empresariais gerenciados (Active Directory / GPO / MDM).

---

## 🔒 Princípios de Segurança e Conformidade

1. **Sem Mecanismos de Bypass**: Não utilizamos injeção de DLLs, técnicas de hook de sistema operacional nem contorno de proteções nativas dos navegadores.
2. **Arquitetura Oficial**: A implantação utiliza as políticas oficiais de grupo disponibilizadas pelo Google (`Chrome Enterprise Policies`) e pela Microsoft (`Microsoft Edge Policies`).
3. **Privacidade Absoluta**: A extensão coleta unicamente o domínio (ex: `sistema.empresa.com.br`, `youtube.com`) e o transmite exclusivamente para o endereço local da máquina (`http://127.0.0.1:5005/active-tab`). Nenhum dado de navegação (URLs completas, caminhos, parâmetros, histórico, cookies ou senhas) é coletado ou transmitido externamente.

---

## 1. Implantação Local / Testes em Máquinas Isoladas

Para testes ou máquinas não ingressadas em domínio Active Directory:

### Google Chrome
1. Abra o navegador e acerte a URL: `chrome://extensions`
2. Ative a chave **Modo do desenvolvedor** (canto superior direito).
3. Clique em **Carregar sem compactação** (Load unpacked).
4. Selecione a pasta permanente:
   ```text
   C:\ProgramData\GivovaMonitor\extension
   ```
5. A extensão será carregada e permanecerá ativa.

### Microsoft Edge
1. Abra o navegador e acerte a URL: `edge://extensions`
2. Ative a chave **Modo do desenvolvedor** (painel lateral esquerdo).
3. Clique em **Carregar descompactada** (Load unpacked).
4. Selecione a pasta permanente:
   ```text
   C:\ProgramData\GivovaMonitor\extension
   ```
5. A extensão estará operacional.

> [!NOTE]
> Como os arquivos da extensão residem em `C:\ProgramData\GivovaMonitor\extension`, a pasta de instalação original (`GivovaMonitorDeploy` no Desktop ou pendrive) pode ser completamente excluída sem afetar a extensão.

---

## 2. Implantação Corporativa Centralizada via Active Directory (GPO)

Em ambientes com controladores de domínio Windows Server, a extensão pode ser forçada e ativada automaticamente sem intervenção do usuário final.

### 2.1 Método A: GPO com Extensão Hospedada Internamente (CRX + Update XML)

Para distribuir a extensão corporativa via servidor Web interno da TI (ex: `https://ti-servidor.givova.local/extensions/`):

1. **Empacotar a extensão em arquivo `.crx`**:
   No Chrome/Edge em `chrome://extensions`, clique em **Empacotar extensão**, aponte para `C:\ProgramData\GivovaMonitor\extension` e gere `givova_extension.crx` e a chave privada `.pem`.
   Anote o **Extension ID** gerado (ex: `abcdefghijklmnopqrstuvwxyzabcdef`).

2. **Criar o manifesto XML de atualização (`updates.xml`)**:
   Hospede no servidor IIS/Nginx interno da TI:
   ```xml
   <?xml version='1.0' encoding='UTF-8'?>
   <gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
     <app appid='SEU_EXTENSION_ID_AQUI'>
       <updatecheck codebase='https://ti-servidor.givova.local/extensions/givova_extension.crx' version='1.0.0' />
     </app>
   </gupdate>
   ```

3. **Configurar a GPO do Google Chrome**:
   - Baixe os modelos administrativos (`chrome.admx` e `google.admx`).
   - No Editor de Gerenciamento de Diretiva de Grupo:
     `Configuração do Computador` → `Modelos Administrativos` → `Google` → `Google Chrome` → `Extensões` → **Configurar a lista de extensões com instalação forçada** (`ExtensionInstallForcelist`).
   - Habilite e adicione o valor:
     ```text
     SEU_EXTENSION_ID_AQUI;https://ti-servidor.givova.local/extensions/updates.xml
     ```

4. **Configurar a GPO do Microsoft Edge**:
   - Baixe os modelos administrativos (`msedge.admx`).
   - No Editor de Diretiva de Grupo:
     `Configuração do Computador` → `Modelos Administrativos` → `Microsoft Edge` → `Extensões` → **Controlar quais extensões são instaladas silenciosamente** (`ExtensionInstallForcelist`).
   - Habilite e adicione o mesmo valor:
     ```text
     SEU_EXTENSION_ID_AQUI;https://ti-servidor.givova.local/extensions/updates.xml
     ```

---

## 3. Implantação via Registro do Windows (GPO / Script de Logon / Intune)

As diretivas corporativas também podem ser configuradas diretamente nas chaves de registro do Windows:

### Para o Google Chrome:
```powershell
$regKey = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
if (-not (Test-Path $regKey)) { New-Item -Path $regKey -Force | Out-Null }
Set-ItemProperty -Path $regKey -Name "1" -Value "SEU_EXTENSION_ID;https://ti-servidor.givova.local/extensions/updates.xml"
```

### Para o Microsoft Edge:
```powershell
$regKey = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist"
if (-not (Test-Path $regKey)) { New-Item -Path $regKey -Force | Out-Null }
Set-ItemProperty -Path $regKey -Name "1" -Value "SEU_EXTENSION_ID;https://ti-servidor.givova.local/extensions/updates.xml"
```

---

## 4. Funcionamento Resiliente e Desacoplado (Extensão Opcional)

O **Givova Monitor Agent** foi arquitetado com desacoplamento estrito:

- **Sem a extensão**: O agente identifica o executável em primeiro plano (ex: `chrome.exe`, `msedge.exe`, `excel.exe`) e reporta `Google Chrome` ou `Microsoft Edge` ao dashboard.
- **Com a extensão**: A extensão envia periodicamente o domínio ativo via POST local para `http://127.0.0.1:5005/active-tab`. O agente vincula o domínio ao navegador em foco e reporta ambos ao servidor.
- Caso o navegador seja fechado ou a porta 5005 esteja indisponível, o agente continua funcionando normalmente sem interrupções ou erros.
