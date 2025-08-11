import hashlib
import os

# 🔍 Daftar hash malware yang sudah diketahui (contoh)
malicious_hashes = {
    "5d41402abc4b2a76b9719d911017c592",  # Contoh hash MD5
    "9e107d9d372bb6826bd81d3542a419d6",  # Contoh lain
}

# 📁 Ganti dengan path folder yang mau discan
target_folder = "./sample_folder"

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        print(f"Gagal baca file {file_path}: {e}")
        return None

def scan_folder(folder_path):
    print(f"Scanning folder: {folder_path}")
    for root, dirs, files in os.walk(folder_path):
        for name in files:
            file_path = os.path.join(root, name)
            file_hash = calculate_md5(file_path)
            if file_hash:
                print(f"{file_path} --> {file_hash}")
                if file_hash in malicious_hashes:
                    print(f"🚨 [ALERT] File mencurigakan ditemukan: {file_path}")
                    # Bisa tambahkan aksi lanjutan: hapus, karantina, dll

scan_folder(target_folder)
