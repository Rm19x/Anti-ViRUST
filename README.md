#  antiViRust Real  Core Engine

RM19X adalah sebuah mesin core antivirus modern dan *cross-platform* yang ditulis menggunakan bahasa pemrograman **Rust**. Proyek ini dibuat untuk memberikan keamanan tingkat tinggi dengan memanfaatkan fitur *memory safety* dari Rust guna menghindari celah keamanan fatal yang sering menyerang perangkat lunak antivirus tradisional (seperti *Buffer Overflow*).

Aplikasi ini menggabungkan analisis biner lokal (Heuristik, Entropi, PE Parser) dengan teknologi isolasi kriptografi untuk mengamankan sistem dari ancaman siber secara nyata.

---

##  Komponen & Kemampuan Keamanan

Antivirus ini mengimplementasikan berbagai modul keamanan esensial yang bekerja secara simultan dalam satu file core engine:

### 1. Detection Engine (Otak Pendeteksi)
* **Signature & Pattern Matching** – Mendeteksi malware berdasarkan signature biner spesifik serta string uji standar internasional (EICAR).
* **Heuristic Analysis** – Menganalisis instruksi biner dan mendeteksi pemanggilan fungsi API Windows yang mencurigakan (seperti *Process Injection* atau *Keylogging*).
* **Shannon Entropy Analysis** – Menghitung tingkat keacakan biner untuk mendeteksi apakah file tersebut merupakan payload Ransomware terenkripsi atau Trojan yang dikompres padat.
* **Macro/VBA Script Detector** – Membedah dokumen kantor (`.doc`, `.xls`) untuk mendeteksi skrip eksekusi otomatis (*Macro Exploit*).
* **Double Extension Blocker** – Mencegah taktik penyamaran ekstensi file klasik yang mencurigakan (contoh: `file.pdf.exe`).
* **Archive Scanner** – Membongkar dan memindai isi file arsip (`.zip`) secara langsung di dalam memori tanpa perlu mengekstraknya ke harddisk.
* **Digital Signature Checker** – Memeriksa validitas blok penandatanganan pada file executable untuk meminimalisir *false positive*.
* **PE (Portable Executable) Header Parser** – Membedah struktur biner file executable Windows (`MZ`) untuk pemetaan profil bahaya.

### 2. System & Cloud Intelligence
* **Process Behavior Guard** – Mitigasi anomali pada pemicu eksekusi file biner berbahaya.
* **USB/External Drive Auto-Scan Trigger** – Mendeteksi jalur *mounting* media penyimpanan eksternal (seperti Flashdisk) untuk memicu pemindaian prioritas tinggi.
* **VirusTotal Cloud Integration** – Integrasi query jaringan HTTPS aman untuk memeriksa reputasi hash global secara langsung ke server VirusTotal.
* **Cross-Platform Hardening Auditor** – Memeriksa konfigurasi keamanan OS. Pada Linux mengaudit hak akses `/etc/shadow`, pada Windows memeriksa elevasi hak akses Administrator.
* **Financial Technical Analytics** – Logika dasar untuk mendeteksi anomali transmisi atau modifikasi data teknis.

### 3. Remediation & Interface
* **Secure Karantina (AES-256-GCM)** – Mengenkripsi file malware yang tertangkap menggunakan enkripsi militer AES-256 agar biner tersebut mati total, tidak dapat dieksekusi, lalu memindahkannya ke folder terisolasi.
* **Beautiful TUI Dashboard** – Antarmuka visual berbasis terminal untuk memantau status pemindaian secara *real-time*.

---

## build
```

cargo run -- ./target_scan

cargo run -- . --audit
const VIRUSTOTAL_API_KEY: &str = "ISI_API_KEY_KAMU_DI_SINI";
