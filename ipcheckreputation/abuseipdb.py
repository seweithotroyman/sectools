import re
import requests
from collections import Counter

# === KONFIGURASI ===
API_KEY = "ISI_API_KEY_ABUSEIPDB_LO"
LOG_FILE = "log_sample.txt"
OUTPUT_FILE = "ip_reputation_results.csv"

# === REGEX IP Address ===
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

def extract_ips_from_log(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            all_ips = re.findall(ip_pattern, content)
            return list(set(all_ips))  # Ambil IP unik
    except FileNotFoundError:
        print(f"File tidak ditemukan: {file_path}")
        return []

def query_abuseipdb(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }

    response = requests.get(url, headers=headers, params=querystring)
    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "ip": ip_address,
            "abuse_score": data['abuseConfidenceScore'],
            "total_reports": data['totalReports'],
            "country": data.get('countryCode', 'N/A'),
            "last_reported": data.get('lastReportedAt', 'N/A')
        }
    else:
        print(f"⚠️ Gagal query IP {ip_address}: {response.status_code}")
        return {
            "ip": ip_address,
            "abuse_score": "Error",
            "total_reports": "-",
            "country": "-",
            "last_reported": "-"
        }

def main():
    print(f"📄 Membaca log dari: {LOG_FILE}")
    ip_list = extract_ips_from_log(LOG_FILE)
    
    if not ip_list:
        print("🚫 Tidak ada IP ditemukan di log.")
        return
    
    print(f"🔍 Menemukan {len(ip_list)} IP unik. Memulai pengecekan ke AbuseIPDB...\n")

    results = []
    for ip in ip_list:
        result = query_abuseipdb(ip)
        results.append(result)
        print(f"✅ {ip} | Abuse Score: {result['abuse_score']}")

    # Simpan ke CSV
    with open(OUTPUT_FILE, "w") as f:
        f.write("IP,Abuse Score,Total Reports,Country,Last Reported\n")
        for r in results:
            f.write(f"{r['ip']},{r['abuse_score']},{r['total_reports']},{r['country']},{r['last_reported']}\n")

    print(f"\n✅ Hasil disimpan ke: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
