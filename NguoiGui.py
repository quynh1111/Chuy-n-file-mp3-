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

# Hàm gửi dữ liệu với độ dài
def send_data(sock, data):
    try:
        data_bytes = data.encode() if isinstance(data, str) else data
        length_bytes = struct.pack('!I', len(data_bytes))
        sock.sendall(length_bytes)
        chunk_size = 65536
        for i in range(0, len(data_bytes), chunk_size):
            sock.sendall(data_bytes[i:i + chunk_size])
        print(f"Gửi dữ liệu thành công ({len(data_bytes)} bytes)")
        time.sleep(0.1)
    except socket.error as e:
        print(f"Lỗi gửi dữ liệu: {e}")
        raise

# Hàm nhận dữ liệu với độ dài
def recv_data(sock):
    try:
        length_bytes = sock.recv(4)
        if not length_bytes:
            print("Không nhận được độ dài dữ liệu")
            return None
        length = struct.unpack('!I', length_bytes)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(min(length - len(data), 65536))
            if not chunk:
                print("Không nhận được dữ liệu đầy đủ")
                return None
            data += chunk
        print(f"Nhận dữ liệu thành công ({len(data)} bytes)")
        return data
    except socket.error as e:
        print(f"Lỗi nhận dữ liệu: {e}")
        return None

# Hàm nhận xác nhận
def recv_ack(sock):
    try:
        ack = recv_data(sock)
        if ack is None or ack.decode() != "ACK":
            raise ValueError(f"Nhận ACK thất bại, nhận được: {ack}")
        print("Nhận ACK thành công")
        time.sleep(0.1)
    except socket.error as e:
        print(f"Lỗi nhận ACK: {e}")
        raise

# 1. Khởi tạo khóa
khoa_rsa_nguoi_gui = RSA.generate(2048)
khoa_phien = get_random_bytes(24)

# 2. Thiết lập server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
host = 'localhost'
port = 12345
server.bind((host, port))
server.listen(1)
print(f"Server khởi động tại {host}:{port}, chờ kết nối...")

try:
    client, addr = server.accept()
    client.settimeout(60)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
    print(f"Kết nối từ: {addr}")

    # 3. Handshake
    print("Bắt đầu handshake...")
    send_data(client, "Hello!")
    response = recv_data(client)
    if response is None or response.decode() != "Ready!":
        print("Handshake thất bại!")
        client.close()
        server.close()
        exit()
    print("Handshake thành công: Nhận Ready!")

    # 4. Nhận khóa công khai của người nhận
    print("Nhận khóa công khai người nhận...")
    data = recv_data(client)
    if data is None:
        print("Không nhận được khóa công khai của người nhận")
        client.close()
        server.close()
        exit()
    try:
        khoa_cong_khai_nguoi_nhan = RSA.import_key(data)
        print("Nhận khóa công khai của người nhận thành công!")
    except ValueError as e:
        print(f"Lỗi import khóa công khai: {e}")
        client.close()
        server.close()
        exit()

    # 5. Tạo và ký metadata
    ten_file = "Mp3_Mau.mp3"
    if not os.path.exists(ten_file):
        print(f"Lỗi: File {ten_file} không tồn tại!")
        client.close()
        server.close()
        exit()

    try:
        audio = MP3(ten_file)
        thoi_luong = audio.info.length
        print(f"Thời lượng file: {thoi_luong} giây")  # Debug
    except Exception as e:
        print(f"Lỗi khi lấy thời lượng file: {e}")
        client.close()
        server.close()
        exit()

    metadata = {
        "ten_file": ten_file,
        "thoi_gian": int(time.time()),
        "thoi_luong": thoi_luong
    }
    metadata_bytes = json.dumps(metadata).encode()
    hash_metadata = SHA512.new(metadata_bytes)
    chu_ky_metadata = pkcs1_15.new(khoa_rsa_nguoi_gui).sign(hash_metadata)

    # 6. Mã hóa khóa phiên
    ma_hoa_rsa = PKCS1_OAEP.new(khoa_cong_khai_nguoi_nhan)
    khoa_phien_ma_hoa = ma_hoa_rsa.encrypt(khoa_phien)
    print(f"Độ dài khóa phiên mã hóa: {len(khoa_phien_ma_hoa)} bytes")  # Debug

    # 7. Chia file MP3 thành 3 đoạn và mã hóa
    kich_thuoc_file = os.path.getsize(ten_file)
    kich_thuoc_doan = kich_thuoc_file // 3
    goi_tin = []

    with open(ten_file, "rb") as f:
        for i in range(3):
            doan = f.read(kich_thuoc_doan) if i < 2 else f.read()
            if not doan:
                print(f"Lỗi: Đoạn {i+1} rỗng!")
                client.close()
                server.close()
                exit()

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
    print("Gửi khóa công khai người gửi...")
    send_data(client, khoa_rsa_nguoi_gui.publickey().export_key())
    recv_ack(client)

    print("Gửi metadata và chữ ký...")
    du_lieu_metadata = {
        "metadata": metadata,
        "chu_ky_metadata": base64.b64encode(chu_ky_metadata).decode()
    }
    send_data(client, json.dumps(du_lieu_metadata))
    recv_ack(client)

    print("Gửi khóa phiên mã hóa...")
    send_data(client, base64.b64encode(khoa_phien_ma_hoa))
    recv_ack(client)

    print("Gửi số lượng gói tin...")
    send_data(client, str(len(goi_tin)))
    recv_ack(client)

    for i, goi in enumerate(goi_tin, 1):
        print(f"Gửi gói tin {i}/{len(goi_tin)}...")
        send_data(client, json.dumps(goi))
        recv_ack(client)
        time.sleep(0.2)

    print("Đã gửi toàn bộ dữ liệu!")

except Exception as e:
    print(f"Lỗi người gửi: {e}")
finally:
    client.close()
    server.close()