from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3, PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from mutagen.mp3 import MP3
import base64
import time
import os
import json
import socket
import struct
import tkinter as tk
from tkinter import filedialog, scrolledtext
import threading

# Hàm gửi dữ liệu với độ dài
def send_data(sock, data):
    try:
        data_bytes = data.encode() if isinstance(data, str) else data
        length_bytes = struct.pack('!I', len(data_bytes))
        sock.sendall(length_bytes)
        chunk_size = 65536
        for i in range(0, len(data_bytes), chunk_size):
            sock.sendall(data_bytes[i:i + chunk_size])
        return f"Gửi dữ liệu thành công ({len(data_bytes)} bytes)"
    except socket.error as e:
        return f"Lỗi gửi dữ liệu: {e}"
    finally:
        time.sleep(0.1)

# Hàm nhận dữ liệu với độ dài
def recv_data(sock):
    try:
        length_bytes = sock.recv(4)
        if not length_bytes:
            return None, "Không nhận được độ dài dữ liệu"
        length = struct.unpack('!I', length_bytes)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(min(length - len(data), 65536))
            if not chunk:
                return None, "Không nhận được dữ liệu đầy đủ"
            data += chunk
        return data, f"Nhận dữ liệu thành công ({len(data)} bytes)"
    except socket.error as e:
        return None, f"Lỗi nhận dữ liệu: {e}"

# Hàm nhận xác nhận
def recv_ack(sock):
    data, msg = recv_data(sock)
    if data is None or data.decode() != "ACK":
        return False, f"Nhận ACK thất bại, nhận được: {data}"
    return True, "Nhận ACK thành công"

# Lớp giao diện người gửi
class SenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Người Gửi - Truyền File MP3 An Toàn")
        self.root.geometry("600x400")
        self.file_path = ""
        self.server = None
        self.client = None

        # Giao diện
        self.label = tk.Label(root, text="Truyền File MP3 An Toàn", font=("Arial", 14))
        self.label.pack(pady=10)

        self.file_label = tk.Label(root, text="Chưa chọn file", font=("Arial", 10))
        self.file_label.pack()

        self.select_button = tk.Button(root, text="Chọn File MP3", command=self.select_file)
        self.select_button.pack(pady=5)

        self.start_button = tk.Button(root, text="Bắt Đầu Gửi", command=self.start_sending, state=tk.DISABLED)
        self.start_button.pack(pady=5)

        self.log_text = scrolledtext.ScrolledText(root, height=15, width=70)
        self.log_text.pack(pady=10)
        self.log_text.insert(tk.END, "Khởi động chương trình người gửi...\n")

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update()

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("MP3 files", "*.mp3")])
        if self.file_path:
            self.file_label.config(text=f"File: {os.path.basename(self.file_path)}")
            try:
                audio = MP3(self.file_path)
                self.log(f"Thời lượng file: {audio.info.length:.2f} giây")
                self.start_button.config(state=tk.NORMAL)
            except Exception as e:
                self.log(f"Lỗi khi lấy thời lượng file: {e}")
                self.start_button.config(state=tk.DISABLED)

    def start_sending(self):
        self.start_button.config(state=tk.DISABLED)
        threading.Thread(target=self.send_file, daemon=True).start()

    def send_file(self):
        try:
            # 1. Khởi tạo khóa
            khoa_rsa_nguoi_gui = RSA.generate(2048)
            khoa_phien = get_random_bytes(24)
            self.log("Đã tạo khóa RSA và khóa phiên 3DES")

            # 2. Thiết lập server
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
            host = 'localhost'
            port = 12345
            self.server.bind((host, port))
            self.server.listen(1)
            self.log(f"Server khởi động tại {host}:{port}, chờ kết nối...")

            self.client, addr = self.server.accept()
            self.client.settimeout(60)
            self.client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
            self.log(f"Kết nối từ: {addr}")

            # 3. Handshake
            self.log("Bắt đầu handshake...")
            msg = send_data(self.client, "Hello!")
            self.log(msg)
            data, msg = recv_data(self.client)
            self.log(msg)
            if data is None or data.decode() != "Ready!":
                self.log("Handshake thất bại!")
                return

            # 4. Nhận khóa công khai người nhận
            self.log("Nhận khóa công khai người nhận...")
            data, msg = recv_data(self.client)
            self.log(msg)
            if data is None:
                self.log("Không nhận được khóa công khai")
                return
            try:
                khoa_cong_khai_nguoi_nhan = RSA.import_key(data)
                self.log("Nhận khóa công khai thành công!")
            except ValueError as e:
                self.log(f"Lỗi import khóa công khai: {e}")
                return

            # 5. Tạo và ký metadata
            if not os.path.exists(self.file_path):
                self.log(f"Lỗi: File {self.file_path} không tồn tại!")
                return
            try:
                audio = MP3(self.file_path)
                thoi_luong = audio.info.length
                self.log(f"Thời lượng file: {thoi_luong:.2f} giây")
            except Exception as e:
                self.log(f"Lỗi khi lấy thời lượng file: {e}")
                return

            metadata = {
                "ten_file": os.path.basename(self.file_path),
                "thoi_gian": int(time.time()),
                "thoi_luong": thoi_luong
            }
            metadata_bytes = json.dumps(metadata).encode()
            hash_metadata = SHA512.new(metadata_bytes)
            chu_ky_metadata = pkcs1_15.new(khoa_rsa_nguoi_gui).sign(hash_metadata)

            # 6. Mã hóa khóa phiên
            ma_hoa_rsa = PKCS1_OAEP.new(khoa_cong_khai_nguoi_nhan)
            khoa_phien_ma_hoa = ma_hoa_rsa.encrypt(khoa_phien)
            self.log(f"Độ dài khóa phiên mã hóa: {len(khoa_phien_ma_hoa)} bytes")

            # 7. Chia file MP3 thành 3 đoạn và mã hóa
            kich_thuoc_file = os.path.getsize(self.file_path)
            kich_thuoc_doan = kich_thuoc_file // 3
            goi_tin = []

            with open(self.file_path, "rb") as f:
                for i in range(3):
                    doan = f.read(kich_thuoc_doan) if i < 2 else f.read()
                    if not doan:
                        self.log(f"Lỗi: Đoạn {i+1} rỗng!")
                        return

                    iv = get_random_bytes(8)
                    ma_hoa_3des = DES3.new(khoa_phien, DES3.MODE_CBC, iv)
                    doan_padding = doan + b"\x00" * (8 - (len(doan) % 8))
                    ban_ma = ma_hoa_3des.encrypt(doan_padding)

                    hash_obj = SHA512.new(iv + ban_ma)
                    hash_doan = hash_obj.hexdigest()
                    chu_ky_doan = pkcs1_15.new(khoa_rsa_nguoi_gui).sign(hash_obj)

                    goi = {
                        "iv": base64.b64encode(iv).decode(),
                        "cipher": base64.b64encode(ban_ma).decode(),
                        "hash": hash_doan,
                        "sig": base64.b64encode(chu_ky_doan).decode()
                    }
                    goi_tin.append(goi)

            # 8. Gửi dữ liệu
            self.log("Gửi khóa công khai người gửi...")
            msg = send_data(self.client, khoa_rsa_nguoi_gui.publickey().export_key())
            self.log(msg)
            success, msg = recv_ack(self.client)
            self.log(msg)
            if not success:
                return

            self.log("Gửi metadata và chữ ký...")
            du_lieu_metadata = {
                "metadata": metadata,
                "chu_ky_metadata": base64.b64encode(chu_ky_metadata).decode()
            }
            msg = send_data(self.client, json.dumps(du_lieu_metadata))
            self.log(msg)
            success, msg = recv_ack(self.client)
            self.log(msg)
            if not success:
                return

            self.log("Gửi khóa phiên mã hóa...")
            msg = send_data(self.client, base64.b64encode(khoa_phien_ma_hoa))
            self.log(msg)
            success, msg = recv_ack(self.client)
            self.log(msg)
            if not success:
                return

            self.log("Gửi số lượng gói tin...")
            msg = send_data(self.client, str(len(goi_tin)))
            self.log(msg)
            success, msg = recv_ack(self.client)
            self.log(msg)
            if not success:
                return

            for i, goi in enumerate(goi_tin, 1):
                self.log(f"Gửi gói tin {i}/{len(goi_tin)}...")
                msg = send_data(self.client, json.dumps(goi))
                self.log(msg)
                success, msg = recv_ack(self.client)
                self.log(msg)
                if not success:
                    return
                time.sleep(0.2)

            self.log("Đã gửi toàn bộ dữ liệu!")

        except Exception as e:
            self.log(f"Lỗi người gửi: {e}")
        finally:
            if self.client:
                self.client.close()
            if self.server:
                self.server.close()
            self.start_button.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = SenderGUI(root)
    root.mainloop()