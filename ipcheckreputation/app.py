import re
from collections import Counter

# Ganti ini dengan path ke file log kamu
log_file_path = "log_sample.txt"

# Regex pattern untuk IP address
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

def extract_ips_from_log(file_path):
    try:
        with open(file_path, 'r') as file:
            log_content = file.read()
            # Cari semua IP address
            ips = re.findall(ip_pattern, log_content)
            return ips
    except FileNotFoundError:
        print(f"File tidak ditemukan: {file_path}")
        return []

def main():
    print(f"📄 Membaca file log: {log_file_path}")
    ip_list = extract_ips_from_log(log_file_path)

    if not ip_list:
        print("🚫 Tidak ada IP ditemukan.")
        return

    # Hitung kemunculan setiap IP
    ip_counter = Counter(ip_list)

    print("\n📊 IP yang ditemukan dan jumlah kemunculannya:")
    for ip, count in ip_counter.most_common():
        print(f"{ip} --> {count}x")

    # Simpan ke file hasil (opsional)
    with open("hasil_ip.csv", "w") as out:
        out.write("IP Address, Jumlah Kemunculan\n")
        for ip, count in ip_counter.items():
            out.write(f"{ip},{count}\n")

    print("\n✅ Hasil disimpan ke: hasil_ip.csv")

if __name__ == "__main__":
    main()
