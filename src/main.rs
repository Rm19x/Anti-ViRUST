use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write, Seek};
use std::path::{Path, PathBuf};
use std::time::Duration;
use sha2::{Sha256, Digest};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::RngCore;
use zip::ZipArchive;
use serde::Deserialize;



const VIRUSTOTAL_API_KEY: &str = "YOUR_REAL_API_KEY_HERE"; // Ganti dengan API Key VT kamu jika ada

#[derive(Deserialize, Debug)]
struct VTResponseData {
    last_analysis_stats: Option<VTStats>,
}
#[derive(Deserialize, Debug)]
struct VTStats {
    malicious: i32,
    undected: i32,
}
#[derive(Deserialize, Debug)]
struct VTResponse {
    data: Option<VTResponseData>,
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_tui_header();
        println!("❌ Penggunaan: cargo run -- <path_target_folder_atau_file>");
        println!("💡 Jalankan dengan argumen tambahan '--audit' untuk memeriksa pengerasan OS ( 19)");
        return Ok(());
    }

    print_tui_header(); // 

    let target = &args[1];
    let path_target = Path::new(target);

    if args.contains(&"--audit".to_string()) {
        run_os_hardening_audit();
        return Ok(());
    }


    if target.contains("media") || target.contains("mnt") || (target.len() == 3 && target.ends_with(":\\")) {
        println!("⚡ [ 16] Perangkat Eksternal/USB Terdeteksi! Memulai Auto-Scan Prioritas Tinggi...");
    }

    let quarantine_dir = Path::new("./quarantine_secure");
    if !quarantine_dir.exists() {
        fs::create_dir(quarantine_dir)?;
    }

    println!("🚀 Memulai Scan Realistis pada: {:?}", path_target);
    println!("-----------------------------------------------------------------");

    if path_target.is_dir() {
        scan_dir_recursive(path_target, quarantine_dir)?;
    } else {
        process_single_file(path_target, quarantine_dir)?;
    }

    println!("\n✨ Proses Pemindaian dan Pengamanan Selesai!");
    Ok(())
}

fn print_tui_header() {
    println!("=================================================================");
    println!("🛡️  Mr.Rm19 antivirus											 🛡️");
    println!("   github.com/Rm19x										       ");
    println!("=================================================================");
}

fn run_os_hardening_audit() {
    println!("🔍 [ 19] Menjalankan Audit Pengerasan Keamanan OS...");
    let shadow_path = Path::new("/etc/shadow");
    if shadow_path.exists() {
        if let Ok(meta) = fs::metadata(shadow_path) {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            if mode & 0o007 != 0 {
                println!("⚠️  KERENTANAN: File /etc/shadow dapat dibaca oleh publik! Risiko kebocoran hash password.");
            } else {
                println!("✅ AMAN: Hak akses /etc/shadow terisolasi dengan baik.");
            }
        }
    } else {
        println!("ℹ️  Info: Bukan sistem berbasis POSIX/Linux standard. Melewati audit shadow file.");
    }
}

fn scan_dir_recursive(dir: &Path, quarantine_dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            scan_dir_recursive(&path, quarantine_dir)?;
        } else {
            process_single_file(&path, quarantine_dir)?;
        }
    }
    Ok(())
}

fn process_single_file(file_path: &Path, quarantine_dir: &Path) -> io::Result<()> {
    let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();

    if file_name.contains(".pdf.exe") || file_name.contains(".txt.exe") || file_name.contains(".docx.exe") {
        println!("⚠️  [  DETEKSI] Ekstensi Ganda Mencurigakan: {}", file_name);
        execute_quarantine(file_path, quarantine_dir)?;
        return Ok(());
    }

    // Baca data biner file asli
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return Ok(()), // Skip jika file dikunci sistem lain
    };
    let mut buffer = Vec::new();
    if file.read_to_end(&mut buffer).is_err() {
        return Ok(());
    }

    if file_name.ends_with(".zip") {
        println!("📦 [ 7] Membuka arsip kompresi: {} untuk pemindaian internal...", file_name);
        let reader = std::io::Cursor::new(&buffer);
        if let Ok(mut archive) = ZipArchive::new(reader) {
            for i in 0..archive.len() {
                if let Ok(mut internal_file) = archive.by_index(i) {
                    let mut internal_buf = Vec::new();
                    if internal_file.read_to_end(&mut internal_buf).is_ok() {
                        analyze_binary_data(&internal_buf, Path::new(internal_file.name()), quarantine_dir, file_path)?;
                    }
                }
            }
        }
    }

    // Pindai file utama
    analyze_binary_data(&buffer, file_path, quarantine_dir, file_path)?;

    Ok(())
}

fn analyze_binary_data(buffer: &[u8], display_path: &Path, quarantine_dir: &Path, source_file_path: &Path) -> io::Result<()> {
    if buffer.is_empty() { return Ok(()); }

    let mut is_malicious = false;
    let mut reason = "";

    let mut hasher = Sha256::new();
    hasher.update(buffer);
    let hash_result = format!("{:x}", hasher.finalize());

    // EICAR Standard Anti-Virus Test String (Kunci pengetesan AV nyata di seluruh dunia)
    if buffer.windows(5).any(|window| window == b"X5O!P") {
        is_malicious = true;
        reason = "EICAR Standard Test Anti-Malware String Terdeteksi!";
    }

    let entropy = calculate_entropy(buffer);
    if entropy > 7.90 && buffer.len() > 10240 { // Skala max 8.0. Nilai > 7.9 berarti biner di-compress padat atau di-encrypt mendadak
        is_malicious = true;
        reason = "Analisis Entropi Tinggi (>7.90). File terindikasi sebagai Ransomware Payload atau Encrypted Trojan.";
    }

    if buffer.starts_with(b"MZ") { // Tanda file .exe / .dll Windows
        if b_contains(buffer, b"VirtualAllocEx") || b_contains(buffer, b"WriteProcessMemory") || b_contains(buffer, b"SetWindowsHookExA") {
            is_malicious = true;
            reason = "Heuristic Analysis: Mengandung pola WinAPI berbahaya untuk Process Injection/Keylogging.";
        }
        
        if !b_contains(buffer, b"Microsoft Executable Signing") && b_contains(buffer, b"VirtualAlloc") && entropy > 7.2 {
            is_malicious = true;
            reason = "PE Malicious Profiling: Executable tidak ditandatangani digital secara valid & memuat fungsi alokasi memori mentah.";
        }
    }

    if b_contains(buffer, b"Sub AutoOpen") || b_contains(buffer, b"ShellExecute") && (display_path.to_string_lossy().contains(".doc") || display_path.to_string_lossy().contains(".xls")) {
        is_malicious = true;
        reason = "Macro Detector: Ditemukan skrip eksekusi otomatis (VBA Macro Exploit) di dalam dokumen.";
    }

    if VIRUSTOTAL_API_KEY != "YOUR_REAL_API_KEY_HERE" && !is_malicious {
        if let Some(vt_verdict) = check_virustotal_cloud(&hash_result) {
            if vt_verdict > 0 {
                is_malicious = true;
                reason = "Cloud Intelligence: VirusTotal mendeteksi file ini sebagai Malware Berbahaya!";
            }
        }
    }

    if is_malicious {
        println!("⚠️  [PROFIL BAHAYA TERDETEKSI] -> {:?}", display_path.file_name().unwrap());
        println!("   | Alasan : {}", reason);
        println!("   | Hash   : {}", hash_result);
        println!("   | Entropi: {:.2}", entropy);
        
        if source_file_path.exists() {
            execute_quarantine(source_file_path, quarantine_dir)?;
        }
    }

    Ok(())
}

// Fungsi bantu pencarian byte pattern
fn b_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let mut entropy = 0.0;
    let len = data.len() as f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn check_virustotal_cloud(file_hash: &str) -> Option<i32> {
    let url = format!("https://www.virustotal.com/api/v3/files/{}", file_hash);
    let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(3)).build().ok()?;
    let response = client.get(&url).header("x-api-key", VIRUSTOTAL_API_KEY).send().ok()?;
    
    if response.status().is_success() {
        if let Ok(vt_data) = response.json::<VTResponse>() {
            if let Some(data) = vt_data.data {
                if let Some(stats) = data.last_analysis_stats {
                    return Some(stats.malicious);
                }
            }
        }
    }
    None
}

fn execute_quarantine(file_path: &Path, quarantine_dir: &Path) -> io::Result<()> {
    let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
    let mut destination = PathBuf::from(quarantine_dir);
    destination.push(format!("{}.locked", file_name));

    println!("🔒 [ 21] Menjalankan Isolasi Karantina Kriptografi AES-256...");

    // 1. Baca file asli
    let mut file_data = Vec::new();
    File::open(file_path)?.read_to_end(&mut file_data)?;

    // 2. Buat Kunci Enkripsi Aman Kriptografis
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new(key);
    
    // 3. Enkripsi data biner virus agar tidak bisa lagi dieksekusi oleh OS secara sengaja/tidak sengaja
    if let Ok(ciphertext) = cipher.encrypt(nonce, file_data.as_slice()) {
        let mut q_file = File::create(&destination)?;
        // Simpan Nonce dan Data Terenkripsi ke file .locked
        q_file.write_all(&nonce_bytes)?;
        q_file.write_all(&ciphertext)?;

        // 4. Hapus file virus asli dari folder asal (Remediation)
        fs::remove_file(file_path)?;
        println!("🛡️  SUKSES: File berbahaya telah dienkripsi penuh dan dipindahkan ke {:?}", destination);
    } else {
        println!("❌ Gagal mengenkripsi file secara aman.");
    }

    Ok(())
}
