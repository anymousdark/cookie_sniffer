# Cookie Sniffer

`Cookie Sniffer` é uma ferramenta educacional em Python para capturar e manipular cookies HTTP/HTTPS e tokens de autenticação em um ambiente de teste ético. Projetada para aprendizado em cibersegurança, a ferramenta analisa pacotes de rede, extrai cookies e tokens, e suporta funcionalidades como injeção via XSS, exportação para extensões de navegador, e simulação de ataques como Evil Twin. Inclui CLI e GUI, sendo ideal para estudantes e profissionais.

⚠️ **Aviso Legal**: Use **apenas em redes próprias** ou com autorização explícita. Capturar cookies sem permissão viola leis como GDPR e CCPA. Cookies não podem ser embutidos diretamente em URLs.

## Funcionalidades
1. Captura cookies de requisições HTTP (`Cookie` e `Set-Cookie`).
2. Suporte a HTTPS via mitmproxy (`--mitm`).
3. Detecção automática de tráfego HTTP/HTTPS com avisos.
4. Filtro para portas 80/443 (`--auto-ports`).
5. Captura passiva de cookies automáticos do navegador.
6. Validação de certificados MITM.
7. Exportação para mitmproxy (`--mitm-dump`).
8. Filtro por domínio, IP, e cabeçalhos HTTP.
9. Modo otimizado para Wi-Fi aberto (`--open-wifi`).
10. Aviso legal interativo antes da captura.
11. Suporte a múltiplos filtros BPF (`--filters`).
12. Exportação para JSONL, SQLite, CSV, Netscape, EditThisCookie, Cookie-Editor, Postman, Burp Suite.
13. Geração de script XSS (`--xss-script`) e bookmarklet (`--bookmarklet`).
14. Análise de cookies (Secure, HttpOnly, SameSite).
15. Auditoria de segurança de cookies (`--audit`).
16. Captura e teste de tokens na URL (`--token-capture`, `--test-tokens`).
17. Simulação de Evil Twin (`--evil-twin`) e sessão no navegador (`--browser-session`).
18. Detecção de vulnerabilidades XSS (`--xss-detect`).
19. Suporte a WebSockets (`--websocket`) e IPv6.
20. Relatórios estatísticos e gráficos (`cookies_graph.png`).

## Flags de Linha de Comando
- `--interfaces <nomes>`: Interfaces de rede (ex.: `eth0,wlan0`).
- `--filters <filtros>`: Filtros BPF (ex.: `tcp port 80,tcp port 443`).
- `--domain-filter <domínio>`: Filtrar por domínio.
- `--ip-filter <ip>`: Filtrar por IP.
- `--header-filter <regex>`: Filtrar por cabeçalho HTTP.
- `--output-dir <diretório>`: Diretório de saída.
- `--gui`: Inicia a interface gráfica.
- `--max-packets <n>`: Número máximo de pacotes.
- `--timeout <segundos>`: Tempo máximo de captura.
- `--silent`: Modo silencioso.
- `--continuous`: Captura contínua até Ctrl+C.
- `--http-method <método>`: Filtrar por método HTTP.
- `--cookie-type <tipo>`: Filtrar por tipo de cookie (session/persistent).
- `--email <endereço>`: Enviar resultados por e-mail.
- `--whatsapp <número>`: Enviar resultados via WhatsApp.
- `--proxy-file <arquivo>`: Arquivo com proxies.
- `--mitm`: Usar mitmproxy para HTTPS.
- `--mitm-dump <arquivo>`: Salvar tráfego mitmproxy.
- `--pcap`: Salvar em .pcap.
- `--wireshark-live`: Exibir em Wireshark ao vivo.
- `--auto-ports`: Filtrar portas 80 e 443.
- `--open-wifi`: Modo Wi-Fi aberto.
- `--test-cookies`: Testar cookies capturados.
- `--test-tokens`: Testar tokens capturados.
- `--xss-script`: Gerar script XSS.
- `--edit-this-cookie`: Exportar para EditThisCookie.
- `--cookie-editor`: Exportar para Cookie-Editor.
- `--token-capture`: Capturar tokens na URL.
- `--xss-detect`: Detectar XSS.
- `--domain-validate`: Validar domínio dos cookies.
- `--bookmarklet`: Gerar bookmarklet.
- `--browser-session`: Gerar script para sessão no navegador.
- `--postman`: Exportar para Postman.
- `--audit`: Auditar segurança dos cookies.
- `--websocket`: Capturar cookies em WebSockets.
- `--burp`: Exportar para Burp Suite.
- `--evil-twin`: Simular Evil Twin.
- `--dry-run`: Simular captura.
- `--tutorial`: Mostrar tutorial interativo.

## Pré-requisitos
- Python 3.6+
- Dependências: `pip install scapy matplotlib requests mitmproxy`
- Sistema operacional: Linux (ex.: Kali Linux); Windows com ajustes.
- Permissões: Modo root para captura (use `sudo`).
- mitmproxy (opcional para HTTPS): `pip install mitmproxy`.
- Wireshark (opcional para `--wireshark-live`).
- Arquivo de configuração: `config.json`.

## Instalação
1. Clone o repositório:
   ```bash
   git clone https://github.com/SEU_USUARIO/cookie-sniffer.git
   cd cookie-sniffer
   ```
2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
3. (Opcional) Configure mitmproxy para HTTPS:
   ```bash
   mitmproxy --set upstream_cert=false
   ```
4. (Opcional) Crie um arquivo `config.json`:
   ```json
   {
       "interfaces": ["eth0"],
       "filters": ["tcp port 80", "tcp port 443"],
       "proxies": [],
       "smtp": {"server": "smtp.gmail.com", "port": 587, "user": "", "password": ""},
       "whatsapp": {"api_url": "", "api_key": ""}
   }
   ```

## Uso
- **Modo CLI**:
   ```bash
   sudo python3 cookie_sniffer.py --interfaces wlan0 --filters "tcp port 80 or tcp port 443" --output-dir ./output --domain-filter "*.facebook.com" --xss-script
   ```
- **Modo GUI**:
   ```bash
   sudo python3 cookie_sniffer.py --gui
   ```
- **Modo Wi-Fi Aberto com Tokens**:
   ```bash
   sudo python3 cookie_sniffer.py --open-wifi --token-capture --output-dir ./output
   ```

## Saídas
- Resultados: `output_dir/cookies.json`, `cookies.jsonl`, `cookies.csv`, `cookies.txt`, `edit_this_cookie.json`, `cookie_editor.json`, `postman_collection.json`, `burp_cookies.txt`, `xss_inject.js`, `bookmarklet.js`, `browser_session.js`, `cookies.db`, `cookie_test.json`, `token_test.json`
- Relatórios: `output_dir/report.json`, `audit_report.json`, `cookies_graph.png`
- Pacotes: `output_dir/capture.pcap` (se `--pcap`)
- Logs: `output_dir/cookie_sniffer.log`

## Exemplo
```bash
sudo python3 cookie_sniffer.py --interfaces eth0 --max-packets 100 --output-dir ./output --email seuemail@gmail.com --xss-script --edit-this-cookie
```
- Captura 100 pacotes, salva resultados, gera script XSS, exporta para EditThisCookie, e envia por e-mail.

## Aviso Ético
- **Uso Autorizado**: Use apenas em redes próprias ou com permissão explícita.
- **Privacidade**: Cookies podem conter dados pessoais. Respeite leis como GDPR e CCPA.
- **Responsabilidade**: O autor não se responsabiliza por uso indevido.

## Contribuições
Contribuições são bem-vindas! Envie pull requests ou abra issues.

## Licença
MIT License. Veja o arquivo `LICENSE`.