import re
import time
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# === KONFIGURASI ===
LOG_FILE = "log_sample.txt"
API_KEY = "ISI_API_KEY_VIRUSTOTAL_LO"
CHECKED_IPS = set()
DELAY_BETWEEN_REQUESTS = 15  # detik
RATE_LIMIT_SLEEP = 60  # fallback kalau error rate-limit
PRIVATE_IP_RANGES = [
    re.compile(r'^10\.'), 
    re.compile(r'^192\.168\.'), 
    re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.')  # 172.16.x.x - 172.31.x.x
]

# === IP Pattern ===
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

def is_private_ip(ip):
    return any(pattern.match(ip) for pattern in PRIVATE_IP_RANGES)

def query_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = { "x-apikey": API_KEY }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data["last_analysis_stats"]
            print(f"🔍 IP: {ip}")
            print(f"  - Malicious : {stats['malicious']}")
            print(f"  - Suspicious: {stats['suspicious']}")
            print(f"  - Harmless  : {stats['harmless']}")
            print(f"  - ASN       : {data.get('as_owner', 'N/A')}")
        else:
            print(f"⚠️ Gagal query IP {ip} (Status {response.status_code})")
            if response.status_code == 429:
                print("⏳ Rate limit tercapai. Tidur 1 menit...")
                time.sleep(RATE_LIMIT_SLEEP)
    except Exception as e:
        print(f"❌ Error saat cek IP: {e}")

class LogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(LOG_FILE):
            try:
                with open(LOG_FILE, "r") as f:
                    lines = f.readlines()[-10:]  # Baca baris terakhir
                    for line in lines:
                        ips = re.findall(ip_pattern, line)
                        for ip in ips:
                            if is_private_ip(ip) or ip in CHECKED_IPS:
                                continue
                            CHECKED_IPS.add(ip)
                            query_virustotal_ip(ip)
                            time.sleep(DELAY_BETWEEN_REQUESTS)
            except Exception as e:
                print(f"❌ Gagal baca file: {e}")

if __name__ == "__main__":
    print(f"🚀 Monitoring file: {LOG_FILE}")
    event_handler = LogHandler()
    observer = Observer()
    observer.schedule(event_handler, ".", recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("🛑 Dihentikan oleh user.")
        observer.stop()

    observer.join()
