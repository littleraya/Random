import argparse
import getpass
import hashlib
import hmac
import json
import sys
from datetime import datetime
from pathlib import Path


BASELINE_DEFAULT = "baseline.json"
BUFFER_SIZE = 1024 * 1024  # 1 MB


def hitung_hash_file(file_path):
    """
    Menghitung hash SHA-256 dari sebuah file.
    File dibaca per bagian kecil supaya aman untuk file besar.
    """
    sha = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            data = file.read(BUFFER_SIZE)
            if not data:
                break
            sha.update(data)

    return sha.hexdigest()


def ambil_password(password_arg=None, konfirmasi=False):
    """
    Mengambil password dari argumen terminal atau input manual.
    Saat membuat baseline, password dikonfirmasi agar tidak salah ketik.
    """
    if password_arg:
        return password_arg

    password = getpass.getpass("Masukkan password HMAC: ")

    if konfirmasi:
        ulangi = getpass.getpass("Ulangi password HMAC: ")
        if password != ulangi:
            print("[ERROR] Password tidak sama.")
            sys.exit(2)

    return password


def cari_semua_file(folder, baseline_path):
    """
    Mengambil semua file dalam folder, termasuk subfolder.
    File baseline tidak ikut dihitung agar hasil scan tidak berubah-ubah.
    """
    daftar_file = []

    for file_path in sorted(folder.rglob("*")):
        if not file_path.is_file():
            continue

        try:
            if file_path.resolve() == baseline_path.resolve():
                continue
        except OSError:
            continue

        daftar_file.append(file_path)

    return daftar_file


def scan_folder(folder, baseline_path):
    """
    Melakukan scan folder dan menghasilkan dictionary:
    nama_file_relatif -> hash_sha256
    """
    hasil_scan = {}
    error_scan = []

    for file_path in cari_semua_file(folder, baseline_path):
        try:
            nama_relatif = file_path.relative_to(folder).as_posix()
            hasil_scan[nama_relatif] = hitung_hash_file(file_path)
        except OSError as error:
            error_scan.append(f"{file_path.name}: {error}")

    return hasil_scan, error_scan


def ubah_ke_json_stabil(data):
    """
    JSON dibuat stabil agar perhitungan HMAC selalu konsisten.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def buat_hmac(data, password):
    """
    Membuat HMAC dari data baseline.
    HMAC digunakan untuk memastikan baseline tidak dimodifikasi sembarangan.
    """
    return hmac.new(
        password.encode("utf-8"),
        ubah_ke_json_stabil(data),
        hashlib.sha256
    ).hexdigest()


def buat_data_baseline(folder, hasil_scan):
    """
    Membentuk data baseline sebelum disimpan ke file JSON.
    """
    return {
        "versi": 1,
        "dibuat_pada": datetime.now().isoformat(),
        "folder": str(folder),
        "algoritma": "sha256",
        "files": hasil_scan
    }


def simpan_baseline(baseline_path, data_baseline, password):
    """
    Menyimpan baseline ke file JSON dan menambahkan HMAC.
    """
    data_simpan = data_baseline.copy()
    data_simpan["hmac"] = buat_hmac(data_baseline, password)

    with open(baseline_path, "w", encoding="utf-8") as file:
        json.dump(data_simpan, file, indent=2, sort_keys=True)
        file.write("\n")


def baca_baseline(baseline_path, password):
    """
    Membaca baseline dan memeriksa validitas HMAC-nya.
    Jika HMAC tidak cocok, baseline dianggap tidak dipercaya.
    """
    try:
        with open(baseline_path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        return None, "File baseline tidak ditemukan."
    except json.JSONDecodeError:
        return None, "File baseline bukan JSON yang valid."
    except OSError as error:
        return None, f"Baseline gagal dibaca: {error}"

    hmac_lama = data.pop("hmac", None)

    if hmac_lama is None:
        return None, "Baseline tidak memiliki HMAC."

    hmac_baru = buat_hmac(data, password)

    if not hmac.compare_digest(hmac_lama, hmac_baru):
        return None, "HMAC tidak valid. Baseline kemungkinan sudah diubah."

    if data.get("algoritma") != "sha256":
        return None, "Algoritma baseline tidak didukung."

    if "files" not in data or not isinstance(data["files"], dict):
        return None, "Format baseline tidak valid."

    return data, None


def perintah_init(args):
    folder = args.folder.resolve()
    baseline_path = args.baseline.resolve()

    if not folder.exists() or not folder.is_dir():
        print(f"[ERROR] Folder tidak valid: {folder}")
        return 2

    password = ambil_password(args.password, konfirmasi=True)

    hasil_scan, daftar_error = scan_folder(folder, baseline_path)
    data_baseline = buat_data_baseline(folder, hasil_scan)

    try:
        simpan_baseline(baseline_path, data_baseline, password)
    except OSError as error:
        print(f"[ERROR] Gagal menyimpan baseline: {error}")
        return 2

    print(f"[INIT] Scan selesai. Total file: {len(hasil_scan)}")
    print(f"[INFO] Baseline disimpan di: {baseline_path}")

    if daftar_error:
        print(f"[WARN] Ada {len(daftar_error)} file yang gagal discan:")
        for error in daftar_error:
            print(f" - {error}")
        return 1

    return 0


def perintah_verify(args):
    folder = args.folder.resolve()
    baseline_path = args.baseline.resolve()

    if not folder.exists() or not folder.is_dir():
        print(f"[ERROR] Folder tidak valid: {folder}")
        return 2

    password = ambil_password(args.password)

    baseline, error = baca_baseline(baseline_path, password)
    if error:
        print(f"[ERROR] {error}")
        return 2

    file_lama = baseline["files"]
    file_baru, daftar_error = scan_folder(folder, baseline_path)

    file_ditambah = sorted(set(file_baru) - set(file_lama))
    file_dihapus = sorted(set(file_lama) - set(file_baru))

    file_diubah = []
    for nama_file in sorted(set(file_lama) & set(file_baru)):
        if file_lama[nama_file] != file_baru[nama_file]:
            file_diubah.append(nama_file)

    jumlah_aman = len(set(file_lama) & set(file_baru)) - len(file_diubah)

    print(f"[CHECK] Total file discan: {len(file_baru)}")
    print(f"[OK] File tidak berubah: {jumlah_aman}")

    for nama_file in file_ditambah:
        print(f"[BARU]  {nama_file}")

    for nama_file in file_dihapus:
        print(f"[HAPUS] {nama_file}")

    for nama_file in file_diubah:
        print(f"[UBAH]  {nama_file}")

    if daftar_error:
        print(f"[WARN] Ada {len(daftar_error)} file yang gagal discan:")
        for error in daftar_error:
            print(f" - {error}")

    ada_perubahan = file_ditambah or file_dihapus or file_diubah or daftar_error

    if ada_perubahan:
        print("[SUMMARY] Perubahan terdeteksi.")
        return 1

    print("[SUMMARY] Tidak ada perubahan. Integritas file valid.")
    return 0


def buat_parser():
    parser = argparse.ArgumentParser(
        description="Program sederhana untuk memantau integritas file menggunakan SHA-256 dan HMAC."
    )

    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path(BASELINE_DEFAULT),
        help=f"Lokasi file baseline. Default: {BASELINE_DEFAULT}"
    )

    subparser = parser.add_subparsers(dest="command", required=True)

    init_parser = subparser.add_parser("init", help="Membuat baseline baru")
    init_parser.add_argument("folder", type=Path, help="Folder yang akan discan")
    init_parser.add_argument("--password", help="Password untuk membuat HMAC")
    init_parser.set_defaults(func=perintah_init)

    verify_parser = subparser.add_parser("verify", help="Memeriksa folder berdasarkan baseline")
    verify_parser.add_argument("folder", type=Path, help="Folder yang akan diperiksa")
    verify_parser.add_argument("--password", help="Password untuk memvalidasi HMAC")
    verify_parser.set_defaults(func=perintah_verify)

    return parser


def main():
    parser = buat_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())