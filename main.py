import socket
import sys
import os
import time
import subprocess
import argparse
import ipaddress
import datetime
import json
import re
import concurrent.futures
import select

# ==============================================================================
# GARUDA SSH ELITE PENTEST & TRACEROUTE SUITE (SINGLE-FILE CONSOLIDATED EDITION)
# ==============================================================================

# ANSI Color Codes (Garuda SSH Red & White + Kali Linux Theme)
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"          # Bright Red (Garuda primary)
WHITE = "\033[97m"        # Bright White (Garuda secondary)
GRAY = "\033[90m"         # Kali Linux dark gray
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"

# Cloudflare Known IPv4 CIDR Blocks
CLOUDFLARE_NETS = [
    ipaddress.ip_network('173.245.48.0/20'),
    ipaddress.ip_network('103.21.244.0/22'),
    ipaddress.ip_network('103.22.200.0/22'),
    ipaddress.ip_network('103.31.4.0/22'),
    ipaddress.ip_network('141.101.64.0/18'),
    ipaddress.ip_network('108.162.192.0/18'),
    ipaddress.ip_network('190.93.240.0/20'),
    ipaddress.ip_network('188.114.96.0/20'),
    ipaddress.ip_network('197.234.240.0/22'),
    ipaddress.ip_network('198.41.128.0/17'),
    ipaddress.ip_network('162.158.0.0/15'),
    ipaddress.ip_network('172.64.0.0/13'),
    ipaddress.ip_network('131.0.72.0/22'),
    ipaddress.ip_network('104.16.0.0/12'),
]

DAYS_ID = ["Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu", "Minggu"]
MONTHS_ID = [
    "", "Januari", "Februari", "Maret", "April", "Mei", "Juni", 
    "Juli", "Agustus", "September", "Oktober", "November", "Desember"
]

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 3306: "MySQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "cpanel", "admin", "api", "ssh", 
    "vpn", "staging", "dev", "webmail", "ns1", "ns2", "remote"
]

IPV4_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

def get_realtime_timestamp():
    now = datetime.datetime.now()
    day_name = DAYS_ID[now.weekday()]
    day = now.day
    month_name = MONTHS_ID[now.month]
    year = now.year
    time_str = now.strftime("%H:%M:%S")
    return f"{day_name}, {day} {month_name} {year} - {time_str} WIB"

def colorize(text, color_code):
    return f"{color_code}{text}{RESET}"

def validate_target(target):
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except socket.gaierror as e:
        raise ValueError(f"Target tidak valid atau tidak dapat di-resolve: {target} ({e})")

def is_cloudflare_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in CLOUDFLARE_NETS:
            if ip in net:
                return True
    except ValueError:
        pass
    return False

def check_cloudflare_status(target, target_ip):
    cf_detected = False
    reverse_ptr = "Tidak tersedia"
    
    if is_cloudflare_ip(target_ip):
        cf_detected = True
        
    try:
        hostname, _, _ = socket.gethostbyaddr(target_ip)
        reverse_ptr = hostname
        if 'cloudflare' in hostname.lower() or 'one.one.one.one' in hostname.lower():
            cf_detected = True
    except Exception:
        reverse_ptr = "Hidden / Direct"

    return cf_detected, reverse_ptr

def print_cloudflare_inspector(target, target_ip, cf_detected, reverse_ptr):
    status_text = colorize("AKTIF (Cloudflare Edge / Network)", RED + BOLD) if cf_detected else colorize("TIDAK TERDETEKSI (Direct Origin)", GREEN)
    
    table_width = 72
    top_border = f"{RED}┌" + "─" * (table_width - 2) + f"┐{RESET}"
    mid_border = f"{RED}├" + "─" * 35 + "┬" + "─" * (table_width - 38) + f"┤{RESET}"
    bot_border = f"{RED}└" + "─" * (table_width - 2) + f"┘{RESET}"
    
    title = f"{WHITE}{BOLD}                 GARUDA SSH CLOUDFLARE INSPECTOR                  {RESET}"
    
    print(top_border)
    print(f"{RED}│{title}{RED}│{RESET}")
    print(mid_border)
    
    rows = [
        ("Target Host / Domain", target),
        ("Resolved Target IP", target_ip),
        ("Reverse DNS (PTR)", reverse_ptr),
        ("Cloudflare Status", status_text)
    ]
    
    for left, right in rows:
        left_str = f" {WHITE}{left:<33}"
        right_str = f" {WHITE}{right:<33}"
        print(f"{RED}│{left_str}{RED}│{right_str}{RED}│{RESET}")
        
    print(bot_border)
    print()

def print_banner():
    now_str = get_realtime_timestamp()
    banner = f"""
{RED} ██████╗  █████╗ ██████╗  ██╗   ██╗██████╗  █████╗      ███████╗███████╗██╗  ██╗
{RED}██╔════╝ ██╔══██╗██╔══██╗ ██║   ██║██╔══██╗██╔══██╗     ██╔════╝██╔════╝██║  ██║
{WHITE}██║  ███╗███████║██████╔╝ ██║   ██║██║  ██║███████║     ███████╗███████║███████║
{WHITE}██║   ██║██╔══██║██╔══██╗ ██║   ██║██║  ██║██╔══██║     ╚════██║╚════██║██╔══██║
{RED}╚██████╔╝██║  ██║██║  ██║ ╚██████╔╝██████╔╝██║  ██║     ███████║███████║██║  ██║
{RED} ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝
{GRAY}═══════════════════════════════════════════════════════════════════════════════════════
{WHITE} [*] SYSTEM CORE: {RED}GARUDA SSH NEURAL KERNEL v55.0.0{WHITE} [KALI LINUX EDITION]
{WHITE} [*] STATUS: {RED}ADVANCED MULTI-PATH TRACEROUTE & CLOUDFLARE INSPECTOR ACTIVE
{WHITE} [*] TIMESTAMP: {RED}{now_str} {WHITE}(UTC+7)
{GRAY}═══════════════════════════════════════════════════════════════════════════════════════{RESET}
"""
    print(banner)

def print_table_header():
    header = f"{WHITE}{BOLD}{'Hop':<4} | {'GARUDA GATEWAY / ROUTER (Multi-Path Detected)':<45} | {'Probes':<8} | {'Status / RTT':<20}{RESET}"
    separator = f"{RED}" + "─" * len(header) + f"{RESET}"
    print(f"{RED}" + "─" * len(header) + f"{RESET}")
    print(header)
    print(separator)

# ==============================================================================
# ELITE PENTEST & RECON MODULES
# ==============================================================================
def quick_port_scan(target_ip, ports=None):
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    open_ports = {}
    print(f"\n{WHITE}[*] {RED}GARUDA SSH RECON{WHITE}: Memulai Quick Port Enumeration pada {RED}{target_ip}{RESET}...")
    
    def check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((target_ip, port))
            s.close()
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                return port, service
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_port, p) for p in ports]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                port, service = res
                open_ports[port] = service
                
                if port in [443, 8443]:
                    url = f"https://{target_ip}:{port}" if port != 443 else f"https://{target_ip}"
                elif port in [80, 8080]:
                    url = f"http://{target_ip}:{port}" if port != 80 else f"http://{target_ip}"
                else:
                    url = f"{service.lower()}://{target_ip}:{port}"
                
                print(f"    {RED}[OPEN]{WHITE} Port {port:<5} ({service}) {GREEN}--> AKTIF{RESET} {GRAY}| Link: {CYAN}{url}{RESET}")

    if not open_ports:
        print(f"    {YELLOW}[!] Tidak ada port utama yang terbuka atau tertutup firewall.{RESET}")
    return open_ports

def banner_grab(target_ip, port=80):
    print(f"\n{WHITE}[*] {RED}GARUDA SSH RECON{WHITE}: Menjalankan Banner Grabbing / HTTP Probe pada {RED}{target_ip}:{port}{RESET}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((target_ip, port))
        request = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: GarudaSSH-Scanner\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode('utf-8'))
        response = s.recv(1024).decode('utf-8', errors='ignore')
        s.close()
        if response:
            print(f"    {RED}[BANNER]{WHITE} Respon Server:")
            for line in response.splitlines()[:5]:
                print(f"      {GRAY}{line}{RESET}")
            return response
    except Exception as e:
        print(f"    {YELLOW}[!] Banner grab warning: {e}{RESET}")
    return None

def analyze_http_security_headers(target_ip, port=80):
    print(f"\n{WHITE}[*] {RED}GARUDA SSH DEEP PENTEST{WHITE}: Menganalisis HTTP Security Headers pada {RED}{target_ip}:{port}{RESET}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.5)
        s.connect((target_ip, port))
        request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: GarudaSSH-Pentest\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode('utf-8'))
        response = s.recv(4096).decode('utf-8', errors='ignore')
        s.close()

        headers_to_check = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Server',
            'X-Powered-By'
        ]

        print(f"    {WHITE}Pemeriksaan Security Headers & Information Disclosure:{RESET}")
        for h in headers_to_check:
            pattern = re.compile(rf"^{h}:\s*(.*)$", re.IGNORECASE | re.MULTILINE)
            match = pattern.search(response)
            if match:
                val = match.group(1).strip()
                if h in ['Server', 'X-Powered-By']:
                    print(f"      {YELLOW}[DISCLOSURE] {h}: {val}{RESET}")
                else:
                    print(f"      {GREEN}[SECURE] {h}: {val}{RESET}")
            else:
                if h not in ['Server', 'X-Powered-By']:
                    print(f"      {RED}[MISSING] {h} (Potensi Vulnerability){RESET}")
    except Exception as e:
        print(f"    {YELLOW}[!] HTTP Header analysis warning: {e}{RESET}")

def subdomain_bruteforce(domain):
    if domain.replace('.', '').isdigit():
        return {}

    found_subs = {}
    print(f"\n{WHITE}[*] {RED}GARUDA SSH RECON{WHITE}: Melakukan Subdomain Enumeration untuk {RED}{domain}{RESET}...")

    def resolve_sub(sub):
        full_host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full_host)
            return full_host, ip
        except socket.gaierror:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(resolve_sub, sub) for sub in COMMON_SUBDOMAINS]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                host, ip = res
                found_subs[host] = ip
                print(f"    {RED}[FOUND]{WHITE} {host:<30} {GREEN}==> {ip}{RESET}")

    if not found_subs:
        print(f"    {YELLOW}[!] Tidak ada subdomain umum yang ditemukan.{RESET}")
    return found_subs

def get_asn_whois(target_ip):
    print(f"\n{WHITE}[*] {RED}GARUDA SSH RECON{WHITE}: Mengambil Intelijen ASN & WHOIS untuk {RED}{target_ip}{RESET}...")
    whois_info = {"ip": target_ip, "asn_org": "Unknown", "country": "Unknown"}
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(('whois.arin.net', 43))
        s.sendall(f"n {target_ip}\r\n".encode('utf-8'))
        
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        
        text = response.decode('utf-8', errors='ignore')
        for line in text.splitlines():
            if "OrgName" in line or "Organization" in line or "NetName" in line or "Country" in line:
                print(f"    {RED}[INTEL]{WHITE} {line.strip()}")
                if "OrgName" in line or "Organization" in line:
                    whois_info["asn_org"] = line.split(":", 1)[1].strip()
                elif "Country" in line:
                    whois_info["country"] = line.split(":", 1)[1].strip()
    except Exception as e:
        print(f"    {YELLOW}[!] WHOIS query warning: {e}{RESET}")
        
    return whois_info

def save_recon_report(target, target_ip, cf_status, open_ports, subdomains, whois_data):
    report = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "target_ip": target_ip,
        "cloudflare_protected": cf_status,
        "whois": whois_data,
        "open_ports": open_ports,
        "subdomains": subdomains
    }
    filename = f"garuda_report_{target.replace('.', '_')}.json"
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"\n{GREEN}[+] Laporan Recon & Intelijen berhasil disimpan ke: {BOLD}{filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Gagal menyimpan laporan: {e}{RESET}")

# ==============================================================================
# NETWORK & PENTEST MODULES
# ==============================================================================
def get_local_ip_info():
    print(f"\n{WHITE}[*] {RED}GARUDA SSH NET-MODULE{WHITE}: Memeriksa Informasi Interface & IP Lokal...")
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print(f"    {RED}[LOCAL IP]{WHITE} {local_ip:<20} ({hostname})")
    except Exception as e:
        print(f"    {YELLOW}[!] Gagal mendapatkan IP lokal: {e}{RESET}")

def analyze_hop_statistics(hop_results):
    print(f"\n{WHITE}{BOLD}┌─────────────────────────────────────────────────────────────┐{RESET}")
    print(f"{WHITE}{BOLD}│              GARUDA SSH ADVANCED LATENCY & JITTER STATS      │{RESET}")
    print(f"{WHITE}{BOLD}├─────┬───────────────────────┬──────────┬──────────┬─────────┤{RESET}")
    print(f"{WHITE}{BOLD}│ Hop │ Gateway IP            │ Min/Avg  │ Jitter   │ Loss %  │{RESET}")
    print(f"{WHITE}{BOLD}├─────┼───────────────────────┼──────────┼──────────┼─────────┤{RESET}")

    for ttl, hop_responses in hop_results:
        if not hop_responses:
            print(f"{RED}│ {ttl:<3} │ {'* * * (Timeout)':<21} │ {'*':<8} │ {'*':<8} │ {'100%':<7} │{RESET}")
            continue

        for ip, rtts in hop_responses.items():
            numeric_rtts = []
            for r in rtts:
                try:
                    val = float(r.replace('ms', '').strip())
                    numeric_rtts.append(val)
                except ValueError:
                    pass

            if numeric_rtts:
                min_rtt = min(numeric_rtts)
                max_rtt = max(numeric_rtts)
                avg_rtt = sum(numeric_rtts) / len(numeric_rtts)
                jitter = max_rtt - min_rtt
                probes_sent = 5
                loss_count = probes_sent - len(numeric_rtts)
                loss_pct = (loss_count / probes_sent) * 100
                
                rtt_summary = f"{min_rtt:.1f}/{avg_rtt:.1f}ms"
                jitter_str = f"{jitter:.1f}ms"
                loss_str = f"{loss_pct:.0f}%"
                
                print(f"{RED}│ {ttl:<3} │ {WHITE}{ip:<21} {RED}│ {WHITE}{rtt_summary:<8} {RED}│ {WHITE}{jitter_str:<8} {RED}│ {YELLOW}{loss_str:<7} {RED}│{RESET}")
            else:
                print(f"{RED}│ {ttl:<3} │ {WHITE}{ip:<21} {RED}│ {'*':<8} │ {'*':<8} │ {'100%':<7} │{RESET}")

    print(f"{WHITE}{BOLD}└─────┴───────────────────────┴──────────┴──────────┴─────────┘{RESET}\n")

def path_mtu_discovery(target_ip):
    print(f"\n{WHITE}[*] {RED}GARUDA SSH NET-MODULE{WHITE}: Menjalankan Path MTU Discovery (PMTUD) ke {RED}{target_ip}{RESET}...")
    mtu_sizes = [1500, 1492, 1400, 1360, 1280]
    
    for mtu in mtu_sizes:
        payload_size = mtu - 28
        if payload_size < 0:
            payload_size = 0
            
        cmd = ['ping', '-c', '1', '-M', 'do', '-s', str(payload_size), target_ip]
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                print(f"    {RED}[PMTUD]{WHITE} MTU {mtu} bytes {GREEN}==> SUKSES (Tanpa Fragmentasi){RESET}")
                return mtu
            else:
                print(f"    {RED}[PMTUD]{WHITE} MTU {mtu} bytes {YELLOW}==> FRAGMENTED / BLOCKED{RESET}")
        except Exception:
            break
    print(f"    {WHITE}[*] Rekomendasi Path MTU optimal: {GREEN}1280 - 1400 bytes{RESET}")
    return 1400

def run_udp_traceroute(target_ip, max_hops=30):
    print(f"\n{WHITE}[*] {RED}GARUDA SSH UDP ENGINE{WHITE}: Menjalankan Dedicated UDP Traceroute (-U) ke {RED}{target_ip}{RESET}...")
    cmd = ['traceroute', '-U', '-n', '-q', '3', '-m', str(max_hops), target_ip]
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"{RED}[!] Gagal menjalankan UDP traceroute: {e}{RESET}")

# ==============================================================================
# ADVANCED TRACEROUTE CORE
# ==============================================================================
class AdvancedTraceroute:
    def __init__(self, target_ip, max_hops=30, probes_per_hop=5, timeout=2.0, interface=None):
        self.target_ip = target_ip
        self.max_hops = max_hops
        self.probes_per_hop = probes_per_hop
        self.timeout = timeout
        self.interface = interface

    def run(self):
        print(f"{WHITE}[*] {RED}GARUDA SSH{WHITE} Engine menginisialisasi pelacakan rute ke target: {BOLD}{self.target_ip}{RESET}")
        if self.interface:
            print(f"{GRAY}[*] Menggunakan Interface Jaringan: {RED}{self.interface}{RESET}")
        print(f"{GRAY}[*] Konfigurasi: Max Hops = {self.max_hops} | Probes/Hop = {self.probes_per_hop} | Mode = Multi-Path Engine{RESET}\n")

        cmd = ['traceroute', '-n', '-q', str(self.probes_per_hop), '-m', str(self.max_hops)]
        if self.interface:
            cmd.extend(['-i', self.interface])
        cmd.append(self.target_ip)
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            target_reached = False
            hop_results = []

            for line in process.stdout:
                line = line.strip()
                if not line or line.startswith('traceroute'):
                    continue
                
                parts = line.split()
                if not parts[0].isdigit():
                    continue
                
                ttl = int(parts[0])
                tokens = parts[1:]
                
                hop_responses = {}
                current_ip = None
                current_rtts = []
                
                i = 0
                while i < len(tokens):
                    token = tokens[i]
                    if token == '*':
                        i += 1
                        continue
                    
                    if IPV4_REGEX.match(token) or ':' in token:
                        if current_ip:
                            if current_ip not in hop_responses:
                                hop_responses[current_ip] = []
                            hop_responses[current_ip].extend(current_rtts)
                        current_ip = token
                        current_rtts = []
                    else:
                        if token != 'ms':
                            try:
                                val = float(token)
                                current_rtts.append(f"{val:.1f}ms")
                            except ValueError:
                                pass
                    i += 1
                
                if current_ip:
                    if current_ip not in hop_responses:
                        hop_responses[current_ip] = []
                    hop_responses[current_ip].extend(current_rtts)

                hop_results.append((ttl, hop_responses))
                self._print_hop_row(ttl, hop_responses)

                for ip in hop_responses.keys():
                    if ip == self.target_ip:
                        target_reached = True

            process.wait()
            if target_reached:
                print(f"\n{RED}[+] {WHITE}GARUDA SSH:{RED} Target {self.target_ip} berhasil dicapai!{RESET}")
            else:
                print(f"\n{WHITE}[*] GARUDA SSH Traceroute selesai.{RESET}")

            return hop_results

        except FileNotFoundError:
            print(f"{RED}[!] Error: Perintah 'traceroute' tidak ditemukan di sistem.{RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{RED}[!] Error saat menjalankan traceroute: {e}{RESET}")
            sys.exit(1)

    def _print_hop_row(self, ttl, hop_responses):
        ttl_str = f"{ttl:2d}"
        
        if not hop_responses:
            print(f"{WHITE}{ttl_str}   | {GRAY}{'* * * (Request Timed Out)':<45}{WHITE} | {0:<8} | {'*':<20}{RESET}")
            return

        unique_ips = list(hop_responses.keys())
        is_multipath = len(unique_ips) > 1

        first = True
        for ip in unique_ips:
            rtts = hop_responses[ip]
            rtt_str = ", ".join(rtts) if rtts else "*"
            probe_count = len(rtts) if rtts else 0
            
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                ip_display = f"{ip} ({hostname})"
            except Exception:
                ip_display = ip

            if first:
                if is_multipath:
                    ip_styled = colorize(ip_display, RED + BOLD)
                else:
                    ip_styled = colorize(ip_display, WHITE)
                
                print(f"{WHITE}{ttl_str}   | {ip_styled:<54} | {probe_count}/{self.probes_per_hop:<6} | {WHITE}{rtt_str}{RESET}")
                if is_multipath:
                    print(f"    {RED}│{WHITE}   {RED}⚠️  [GARUDA DETECT]: Multi-Path Routing / Load Balancer terdeteksi!{RESET}")
                first = False
            else:
                alt_styled = colorize(ip_display, RED + BOLD)
                print( f"    {RED}│{WHITE} ↳ {alt_styled:<52} | {probe_count}/{self.probes_per_hop:<6} | {WHITE}{rtt_str}{RESET}")

# ==============================================================================
# MAIN CONTROLLER & INTERACTIVE MENU
# ==============================================================================
def select_network_interface():
    print(f"{WHITE}{BOLD}[ GARUDA SSH - ADVANCED MODULE & NETWORK SELECTOR ]{RESET}")
    print(f"{GRAY}Pilih jalur jaringan atau modul operasional yang diinginkan:{RESET}")
    print(f"  {RED}[1]{WHITE} 📡 Jaringan WiFi (Interface: wlan0)")
    print(f"  {RED}[2]{WHITE} 📶 Data Seluler / Cellular (Interface: ccmni0)")
    print(f"  {RED}[3]{WHITE} ⚡ TCP SYN Traceroute Mode (Port 80/443 Bypass)")
    print(f"  {RED}[4]{WHITE} 🛡️ Cloudflare Deep Inspector & CDN Analysis")
    print(f"  {RED}[5]{WHITE} 🔄 Multi-Path Load Balancer Stress Probe (10 Probes/Hop)")
    print(f"  {RED}[6]{WHITE} 🕵️ Elite Pentest & Recon Suite (Port Scan + WHOIS + Traceroute)")
    print(f"  {RED}[7]{WHITE} 🚀 Dedicated UDP Traceroute Mode (Protokol UDP)")
    print(f"  {RED}[8]{WHITE} ⚡ Elite Deep Pentest Engine (Security Headers + Attack Surface)")
    print(f"  {RED}[9]{WHITE} 🌐 Default / Auto Routing (Sistem)")
    
    try:
        choice = input(f"\n{WHITE}┌──({RED}garuda㉿ssh-sec{WHITE})-[{GRAY}module-select{WHITE}]\n└─{RED}#{WHITE} Masukkan pilihan [1-9] (default 9): {RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{RED}[!] Dibatalkan oleh pengguna.{RESET}")
        sys.exit(0)

    config = {
        'interface': None,
        'probes': 5,
        'mode': 'standard'
    }

    if choice == '1':
        config['interface'] = 'wlan0'
        print(f"{RED}[*] Menggunakan jalur WiFi (wlan0){RESET}")
    elif choice == '2':
        config['interface'] = 'ccmni0'
        print(f"{RED}[*] Menggunakan jalur Data Seluler (ccmni0){RESET}")
    elif choice == '3':
        config['mode'] = 'tcp'
        print(f"{RED}[*] Modul TCP SYN Traceroute diaktifkan.{RESET}")
    elif choice == '4':
        config['mode'] = 'deep_cloudflare'
        print(f"{RED}[*] Modul Cloudflare Deep Inspector diaktifkan.{RESET}")
    elif choice == '5':
        config['probes'] = 10
        print(f"{RED}[*] Modul Stress Probe (10 Probes/Hop) diaktifkan.{RESET}")
    elif choice == '6':
        config['mode'] = 'elite_recon'
        print(f"{RED}[*] Modul Elite Pentest & Recon Suite diaktifkan.{RESET}")
    elif choice == '7':
        config['mode'] = 'udp_traceroute'
        print(f"{RED}[*] Modul Dedicated UDP Traceroute diaktifkan.{RESET}")
    elif choice == '8':
        config['mode'] = 'deep_pentest'
        print(f"{RED}[*] Modul Elite Deep Pentest Engine diaktifkan.{RESET}")
    else:
        print(f"{RED}[*] Menggunakan Default / Auto Routing{RESET}")

    return config

def main():
    parser = argparse.ArgumentParser(
        description="GARUDA SSH - Elite Pentest & Advanced Multi-Path Traceroute Suite (Single-File Edition)"
    )
    parser.add_argument("target", nargs="?", help="IP address atau Domain tujuan (contoh: 8.8.8.8 atau google.com)")
    parser.add_argument("-p", "--probes", type=int, default=5, help="Jumlah probe per hop (default: 5)")
    parser.add_argument("-m", "--max-hops", type=int, default=30, help="Jumlah maksimal hops (default: 30)")
    parser.add_argument("-t", "--timeout", type=float, default=2.0, help="Timeout per probe dalam detik (default: 2.0)")
    parser.add_argument("--wifi", action="store_true", help="Gunakan jaringan WiFi (wlan0)")
    parser.add_argument("--data", action="store_true", help="Gunakan Data Seluler (ccmni0)")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Spesifikasi interface jaringan secara manual")

    args = parser.parse_args()

    print_banner()

    interface = args.interface
    probes = args.probes
    mode = 'standard'

    if args.wifi:
        interface = 'wlan0'
    elif args.data:
        interface = 'ccmni0'
    elif not interface:
        cfg = select_network_interface()
        interface = cfg['interface']
        if cfg['probes'] != 5:
            probes = cfg['probes']
        mode = cfg['mode']

    target = args.target
    if not target:
        try:
            target = input(f"\n{WHITE}┌──({RED}garuda㉿ssh-sec{WHITE})-[{GRAY}target-input{WHITE}]\n└─{RED}#{WHITE} Masukkan IP / Domain target: {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{RED}[!] Dibatalkan oleh pengguna.{RESET}")
            sys.exit(0)

    if not target:
        print(f"{RED}[x] Error: Target tidak boleh kosong!{RESET}")
        sys.exit(1)

    get_local_ip_info()

    print(f"\n{WHITE}[*] GARUDA SSH Resolver memproses target: {RED}{target}{RESET}")
    if interface:
        print(f"{WHITE}[*] Interface terpilih: {RED}{interface}{RESET}")
    if mode != 'standard':
        print(f"{WHITE}[*] Mode Operasional: {RED}{mode.upper()}{RESET}")

    try:
        target_ip, original_target = validate_target(target)
        print(f"{WHITE}[*] Target resolved: {original_target} -> {RED}{target_ip}{RESET}\n")
    except ValueError as e:
        print(f"{RED}[x] Error: {e}{RESET}")
        sys.exit(1)

    cf_detected, reverse_ptr = check_cloudflare_status(original_target, target_ip)
    print_cloudflare_inspector(original_target, target_ip, cf_detected, reverse_ptr)

    if mode == 'udp_traceroute':
        run_udp_traceroute(target_ip, max_hops=args.max_hops)
        print(f"\n{RED}[*] {WHITE}GARUDA SSH UDP Traceroute selesai.{RESET}\n")
        return

    open_ports = {}
    subdomains = {}
    whois_data = {}

    if mode in ['elite_recon', 'deep_cloudflare', 'deep_pentest']:
        whois_data = get_asn_whois(target_ip)
        open_ports = quick_port_scan(target_ip)
        if 80 in open_ports or 443 in open_ports:
            banner_grab(target_ip, port=80 if 80 in open_ports else 443)
            analyze_http_security_headers(target_ip, port=80 if 80 in open_ports else 443)
        if mode in ['elite_recon', 'deep_pentest']:
            subdomains = subdomain_bruteforce(original_target)

    path_mtu_discovery(target_ip)

    print_table_header()

    tracer = AdvancedTraceroute(
        target_ip=target_ip,
        max_hops=args.max_hops,
        probes_per_hop=probes,
        timeout=args.timeout,
        interface=interface
    )
    
    hop_results = tracer.run()

    if hop_results:
        analyze_hop_statistics(hop_results)

    if mode in ['elite_recon', 'deep_cloudflare', 'deep_pentest']:
        save_recon_report(original_target, target_ip, cf_detected, open_ports, subdomains, whois_data)

    print(f"\n{RED}[*] {WHITE}GARUDA SSH Elite Suite selesai.{RESET}\n")

if __name__ == "__main__":
    main()
