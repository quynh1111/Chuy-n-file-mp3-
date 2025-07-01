import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3, PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
import base64
import json
import socket
import os
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

# Hàm gửi xác nhận
def send_ack(sock):
    msg = send_data(sock, "ACK")
    return True, msg

# Lớp giao diện người nhận
class ReceiverGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Người Nhận - Truyền File MP3 An Toàn")
        self.root.geometry("600x400")
        self.output_dir = ""
        self.client = None

        # Giao diện
        self.label = tk.Label(root, text="Nhận File MP3 An Toàn", font=("Arial", 14))
        self.label.pack(pady=10)

        self.dir_label = tk.Label(root, text="Chưa chọn thư mục lưu", font=("Arial", 10))
        self.dir_label.pack()

        self.select_button = tk.Button(root, text="Chọn Thư Mục Lưu", command=self.select_directory)
        self.select_button.pack(pady=5)

        self.start_button = tk.Button(root, text="Bắt Đầu Nhận", command=self.start_receiving, state=tk.DISABLED)
        self.start_button.pack(pady=5)

        self.log_text = scrolledtext.ScrolledText(root, height=15, width=70)
        self.log_text.pack(pady=10)
        self.log_text.insert(tk.END, "Khởi động chương trình người nhận...\n")

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update()

    def select_directory(self):
        self.output_dir = filedialog.askdirectory()
        if self.output_dir:
            self.dir_label.config(text=f"Thư mục lưu: {self.output_dir}")
            self.start_button.config(state=tk.NORMAL)

    def start_receiving(self):
        self.start_button.config(state=tk.DISABLED)
        threading.Thread(target=self.receive_file, daemon=True).start()

    def receive_file(self):
        try:
            # 1. Tạo cặp khóa RSA
            khoa_rsa_nguoi_nhan = RSA.generate(2048)
            khoa_rieng_nguoi_nhan = khoa_rsa_nguoi_nhan
            khoa_cong_khai_nguoi_nhan = khoa_rsa_nguoi_nhan.publickey()
            self.log("Đã tạo cặp khóa RSA")

            # 2. Kết nối đến server
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
            host = 'localhost'
            port = 12345
            self.client.connect((host, port))
            self.client.settimeout(60)
            self.log(f"Kết nối đến server {host}:{port}")

            # 3. Handshake
            self.log("Bắt đầu handshake...")
            data, msg = recv_data(self.client)
            self.log(msg)
            if data is None or data.decode() != "Hello!":
                self.log("Handshake thất bại!")
                return
            msg = send_data(self.client, "Ready!")
            self.log(msg)

            # 4. Gửi khóa công khai
            self.log("Gửi khóa công khai người nhận...")
            msg = send_data(self.client, khoa_cong_khai_nguoi_nhan.export_key())
            self.log(msg)

            # 5. Nhận khóa công khai người gửi
            self.log("Nhận khóa công khai người gửi...")
            data, msg = recv_data(self.client)
            self.log(msg)
            if data is None:
                self.log("Không nhận được khóa công khai")
                return
            try:
                khoa_cong_khai_nguoi_gui = RSA.import_key(data)
                success, msg = send_ack(self.client)
                self.log(msg)
                if not success:
                    return
            except ValueError as e:
                self.log(f"Lỗi import khóa công khai: {e}")
                return

            # 6. Nhận và xác minh metadata
            self.log("Nhận metadata...")
            data, msg = recv_data(self.client)
            self.log(msg)
            if data is None:
                self.log("Không nhận được metadata")
                return
            try:
                du_lieu_metadata = json.loads(data.decode())
                success, msg = send_ack(self.client)
                self.log(msg)
                metadata_nhan = du_lieu_metadata["metadata"]
                chu_ky_metadata_nhan = base64.b64decode(du_lieu_metadata["chu_ky_metadata"])
                hash_metadata = SHA512.new(json.dumps(metadata_nhan).encode())
                pkcs1_15.new(khoa_cong_khai_nguoi_gui).verify(hash_metadata, chu_ky_metadata_nhan)
                self.log(f"Xác minh chữ ký metadata thành công! Thời lượng: {metadata_nhan['thoi_luong']:.2f} giây")
            except (json.JSONDecodeError, ValueError) as e:
                self.log(f"Lỗi xử lý metadata: {e}")
                return

            # 7. Nhận và giải mã khóa phiên
            self.log("Nhận khóa phiên mã hóa...")
            data, msg = recv_data(self.client)
            self.log(msg)
            if data is None:
                self.log("Không nhận được khóa phiên")
                return
            success, msg = send_ack(self.client)
            self.log(msg)
            try:
                khoa_phien_ma_hoa_nhan = base64.b64decode(data)
                self.log(f"Độ dài khóa phiên mã hóa: {len(khoa_phien_ma_hoa_nhan)} bytes")
                giai_ma_rsa = PKCS1_OAEP.new(khoa_rieng_nguoi_nhan)
                khoa_phien = giai_ma_rsa.decrypt(khoa_phien_ma_hoa_nhan)
                self.log("Giải mã khóa phiên thành công!")
            except (ValueError, base64.binascii.Error) as e:
                self.log(f"Giải mã khóa phiên thất bại: {e}")
                return

            # 8. Nhận số lượng gói tin
            self.log("Nhận số lượng gói tin...")
            data, msg = recv_data(self.client)
            self.log(msg)
            if data is None:
                self.log("Không nhận được số lượng gói tin")
                return
            try:
                so_luong_goi = int(data.decode())
                success, msg = send_ack(self.client)
                self.log(msg)
                self.log(f"Số lượng gói tin: {so_luong_goi}")
            except ValueError as e:
                self.log(f"Lỗi xử lý số lượng gói tin: {e}")
                return

            # 9. Nhận và xử lý gói tin
            goi_tin_nhan = []
            for i in range(so_luong_goi):
                self.log(f"Nhận gói tin {i+1}/{so_luong_goi}...")
                data, msg = recv_data(self.client)
                self.log(msg)
                if data is None:
                    self.log(f"Không nhận được gói tin {i+1}")
                    return
                try:
                    goi = json.loads(data.decode())
                    success, msg = send_ack(self.client)
                    self.log(msg)
                    goi_tin_nhan.append(goi)
                except json.JSONDecodeError as e:
                    self.log(f"Lỗi xử lý gói tin {i+1}: {e}")
                    return

            file_dau_ra = os.path.join(self.output_dir, "Mp3_Mau_reconstructed.mp3")
            with open(file_dau_ra, "wb") as f:
                for i, goi in enumerate(goi_tin_nhan, 1):
                    try:
                        iv = base64.b64decode(goi["iv"])
                        ban_ma = base64.b64decode(goi["cipher"])
                        hash_doan = goi["hash"]
                        chu_ky_doan = base64.b64decode(goi["sig"])

                        hash_obj = SHA512.new(iv + ban_ma)
                        pkcs1_15.new(khoa_cong_khai_nguoi_gui).verify(hash_obj, chu_ky_doan)
                        self.log(f"Xác minh chữ ký đoạn {i} thành công!")

                        if hash_obj.hexdigest() != hash_doan:
                            self.log(f"Kiểm tra hash đoạn {i} thất bại!")
                            return

                        giai_ma_3des = DES3.new(khoa_phien, DES3.MODE_CBC, iv)
                        doan = giai_ma_3des.decrypt(ban_ma).rstrip(b"\x00")
                        f.write(doan)
                        self.log(f"Giải mã đoạn {i} thành công!")
                    except (ValueError, KeyError) as e:
                        self.log(f"Lỗi xử lý đoạn {i}: {e}")
                        return

            self.log(f"Tái tạo file thành công: {file_dau_ra}")

        except Exception as e:
            self.log(f"Lỗi người nhận: {e}")
        finally:
            if self.client:
                self.client.close()
            self.start_button.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = ReceiverGUI(root)
    root.mainloop()