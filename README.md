```text
 ██████╗  █████╗ ██████╗  ██╗   ██╗██████╗  █████╗      ███████╗███████╗██╗  ██╗
██╔════╝ ██╔══██╗██╔══██╗ ██║   ██║██╔══██╗██╔══██╗     ██╔════╝██╔════╝██║  ██║
██║  ███╗███████║██████╔╝ ██║   ██║██║  ██║███████║     ███████╗███████║███████║
██║   ██║██╔══██║██╔══██╗ ██║   ██║██║  ██║██╔══██║     ╚════██║╚════██║██╔══██║
╚██████╔╝██║  ██║██║  ██║ ╚██████╔╝██████╔╝██║  ██║     ███████║███████║██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝         
═══════════════════════════════════════════════════════════════════════════════════════
 [*] SYSTEM CORE: GARUDA SSH NEURAL KERNEL v55.0.0 [KALI LINUX EDITION]
 [*] STATUS: ADVANCED MULTI-PATH TRACEROUTE & CLOUDFLARE INSPECTOR ACTIVE
 [*] TIMESTAMP: Real-time WIB (UTC+7)
═══════════════════════════════════════════════════════════════════════════════════════
```

# GARUDA SSH - Elite Pentest & Advanced Multi-Path Traceroute Suite

Tool CLI berbasis Python kelas profesional dengan branding **GARUDA SSH Neural Kernel (v55.0.0)** dan tema **Kali Linux** (kombinasi warna Merah-Putih) yang dirancang untuk melakukan penelusuran IP tingkat lanjut, deteksi **Multi-Path Routing / Load Balancing**, *Cloudflare Deep Inspector*, serta rangkaian *Elite Recon & Network Intelligence Suite*.

---

## 🚀 Fitur Utama & Modul Tersedia

Saat program dijalankan, menu interaktif Kali Linux Garuda SSH akan menampilkan **9 Opsi Modul Lanjutan**:

```text
[ GARUDA SSH - ADVANCED MODULE & NETWORK SELECTOR ]
Pilih jalur jaringan atau modul operasional yang diinginkan:
  [1] 📡 Jaringan WiFi (Interface: wlan0)
  [2] 📶 Data Seluler / Cellular (Interface: ccmni0)
  [3] ⚡ TCP SYN Traceroute Mode (Port 80/443 Bypass)
  [4] 🛡️ Cloudflare Deep Inspector & CDN Analysis
  [5] 🔄 Multi-Path Load Balancer Stress Probe (10 Probes/Hop)
  [6] 🕵️ Elite Pentest & Recon Suite (Port Scan + WHOIS + Traceroute)
  [7] 🚀 Dedicated UDP Traceroute Mode (Protokol UDP)
  [8] ⚡ Elite Deep Pentest Engine (Security Headers + Attack Surface)
  [9] 🌐 Default / Auto Routing (Sistem)
```

### Rincian Modul Intelijen:
1. **Real-time Kali Banner & Timestamp**: Banner ASCII art GARUDA SSH dengan System Core Neural Kernel v55.0.0 dan penanggalan waktu nyata (real-time) berformat bahasa Indonesia (WIB / UTC+7).
2. **Cloudflare Inspector**: Tabel deteksi Cloudflare Edge / Network (menampilkan Target Host di kiri dan Resolved IP / Status di kanan).
3. **Quick Port Enumeration with URLs**: Memindai port utama yang terbuka dan langsung menampilkan tautan URL akses cepat dengan format klik (`http://` / `https://`).
4. **HTTP Security Headers Analyzer**: Menganalisis header keamanan web (`HSTS`, `CSP`, `X-Frame-Options`, dll.) dan mendeteksi potensi *Information Disclosure* (`Server`, `X-Powered-By`).
5. **ASN & WHOIS Intelligence**: Mengambil informasi organisasi dan ASN target secara langsung via protokol WHOIS port 43.
6. **Subdomain Enumeration**: Melakukan resolusi DNS otomatis untuk subdomain populer.
7. **Path MTU Discovery (PMTUD)**: Menguji ukuran MTU jalur jaringan optimal tanpa fragmentasi.
8. **Advanced Latency, Jitter & Loss Analyzer**: Menampilkan tabel statistik komprehensif mencakup Min/Avg RTT, Jitter, dan persentase Packet Loss per hop.
9. **Automated JSON Report Exporter**: Menyimpan laporan intelijen lengkap ke dalam file `garuda_report_<target>.json`.

---

## 🛠️ Cara Penggunaan (Single-File Architecture)

Semua fungsionalitas telah dikonsolidasikan ke dalam satu file tunggal yang sangat portabel: **`main.py`**.

```bash
# Menjalankan secara interaktif (memunculkan menu 9 pilihan modul)
python3 main.py

# Langsung menentukan target IP atau Domain
python3 main.py 1.1.1.1
python3 main.py google.com

# Menggunakan flag interface langsung
python3 main.py --wifi 8.8.8.8
python3 main.py --data 1.1.1.1
```

## 📋 Argumen CLI
- `target`: IP address atau Domain tujuan (opsional, jika kosong akan diminta via input interaktif).
- `-p`, `--probes`: Jumlah probe per hop (default: 5).
- `-m`, `--max-hops`: Jumlah maksimal hops (default: 30).
- `-t`, `--timeout`: Timeout per probe dalam detik (default: 2.0).
- `--wifi`: Menggunakan interface WiFi (`wlan0`).
- `--data`: Menggunakan interface Data Seluler (`ccmni0`).
