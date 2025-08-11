import re
import requests
import time

# === KONFIGURASI ===
API_KEY = "ISI_API_KEY_VIRUSTOTAL_LO"
LOG_FILE = "log_sample.txt"
OUTPUT_FILE = "ip_vt_results.csv"

# === REGEX IP Address ===
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

def extract_ips_from_log(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            all_ips = re.findall(ip_pattern, content)
            return list(set(all_ips))  # Hanya IP unik
    except FileNotFoundError:
        print(f"❌ File tidak ditemukan: {file_path}")
        return []

def query_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()["data"]["attributes"]
        stats = data["last_analysis_stats"]
        return {
            "ip": ip,
            "harmless": stats["harmless"],
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": stats["undetected"],
            "asn": data.get("as_owner", "N/A"),
            "last_analysis": data.get("last_analysis_date", "N/A")
        }
    else:
        print(f"⚠️ Gagal query IP {ip} (Status {response.status_code})")
        return {
            "ip": ip,
            "harmless": "-",
            "malicious": "-",
            "suspicious": "-",
            "undetected": "-",
            "asn": "-",
            "last_analysis": "-"
        }

def main():
    print(f"📄 Membaca log: {LOG_FILE}")
    ip_list = extract_ips_from_log(LOG_FILE)

    if not ip_list:
        print("🚫 Tidak ada IP ditemukan.")
        return

    print(f"🔍 Ditemukan {len(ip_list)} IP unik. Cek ke VirusTotal...\n")

    results = []

    for idx, ip in enumerate(ip_list, start=1):
        print(f"🔎 [{idx}/{len(ip_list)}] Query IP: {ip}")
        result = query_virustotal_ip(ip)
        results.append(result)
        time.sleep(15)  # Hindari rate limit (gratisan: 4 requests/menit)

    # Simpan ke CSV
    with open(OUTPUT_FILE, "w") as f:
        f.write("IP,Malicious,Suspicious,Harmless,Undetected,ASN,Last Analysis\n")
        for r in results:
            f.write(f"{r['ip']},{r['malicious']},{r['suspicious']},{r['harmless']},{r['undetected']},{r['asn']},{r['last_analysis']}\n")

    print(f"\n✅ Hasil disimpan ke: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
