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

# Hàm gửi xác nhận
def send_ack(sock):
    try:
        send_data(sock, "ACK")
        print("Gửi ACK thành công")
        time.sleep(0.1)
    except socket.error as e:
        print(f"Lỗi gửi ACK: {e}")
        raise

# 1. Tạo cặp khóa RSA
khoa_rsa_nguoi_nhan = RSA.generate(2048)
khoa_rieng_nguoi_nhan = khoa_rsa_nguoi_nhan
khoa_cong_khai_nguoi_nhan = khoa_rsa_nguoi_nhan.publickey()

# 2. Kết nối đến server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
host = 'localhost'
port = 12345

try:
    client.connect((host, port))
    client.settimeout(60)
    print(f"Kết nối đến server {host}:{port}")

    # 3. Handshake
    print("Bắt đầu handshake...")
    response = recv_data(client)
    if response is None or response.decode() != "Hello!":
        print("Handshake thất bại!")
        client.close()
        exit()
    send_data(client, "Ready!")
    print("Handshake thành công: Gửi Ready!")

    # 4. Gửi khóa công khai của người nhận
    print("Gửi khóa công khai người nhận...")
    send_data(client, khoa_cong_khai_nguoi_nhan.export_key())
    print("Đã gửi khóa công khai của người nhận!")

    # 5. Nhận khóa công khai của người gửi
    print("Nhận khóa công khai người gửi...")
    data = recv_data(client)
    if data is None:
        print("Không nhận được khóa công khai của người gửi")
        client.close()
        exit()
    try:
        khoa_cong_khai_nguoi_gui = RSA.import_key(data)
        send_ack(client)
        print("Nhận khóa công khai của người gửi thành công!")
    except ValueError as e:
        print(f"Lỗi import khóa công khai: {e}")
        client.close()
        exit()

    # 6. Nhận và xác minh metadata
    print("Nhận metadata...")
    data = recv_data(client)
    if data is None:
        print("Không nhận được metadata")
        client.close()
        exit()
    try:
        du_lieu_metadata = json.loads(data.decode())
        send_ack(client)
        metadata_nhan = du_lieu_metadata["metadata"]
        chu_ky_metadata_nhan = base64.b64decode(du_lieu_metadata["chu_ky_metadata"])
        metadata_bytes = json.dumps(metadata_nhan).encode()
        hash_metadata = SHA512.new(metadata_bytes)
        pkcs1_15.new(khoa_cong_khai_nguoi_gui).verify(hash_metadata, chu_ky_metadata_nhan)
        print(f"Xác minh chữ ký metadata thành công! Thời lượng: {metadata_nhan['thoi_luong']} giây")
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Lỗi xử lý metadata: {e}")
        client.close()
        exit()

    # 7. Nhận và giải mã khóa phiên
    print("Nhận khóa phiên mã hóa...")
    khoa_phien_ma_hoa_nhan = recv_data(client)
    if khoa_phien_ma_hoa_nhan is None:
        print("Không nhận được khóa phiên mã hóa")
        client.close()
        exit()
    send_ack(client)
    try:
        khoa_phien_ma_hoa_nhan = base64.b64decode(khoa_phien_ma_hoa_nhan)  # Giải mã Base64
        print(f"Độ dài khóa phiên mã hóa: {len(khoa_phien_ma_hoa_nhan)} bytes")  # Debug
        giai_ma_rsa = PKCS1_OAEP.new(khoa_rieng_nguoi_nhan)
        khoa_phien = giai_ma_rsa.decrypt(khoa_phien_ma_hoa_nhan)
        print("Giải mã khóa phiên thành công!")
    except (ValueError, base64.binascii.Error) as e:
        print(f"Giải mã khóa phiên thất bại: {e}")
        client.close()
        exit()

    # 8. Nhận số lượng gói tin
    print("Nhận số lượng gói tin...")
    data = recv_data(client)
    if data is None:
        print("Không nhận được số lượng gói tin")
        client.close()
        exit()
    try:
        so_luong_goi = int(data.decode())
        send_ack(client)
        print(f"Số lượng gói tin: {so_luong_goi}")
    except ValueError as e:
        print(f"Lỗi xử lý số lượng gói tin: {e}")
        client.close()
        exit()

    # 9. Nhận và xử lý các gói tin
    goi_tin_nhan = []
    for i in range(so_luong_goi):
        print(f"Nhận gói tin {i+1}/{so_luong_goi}...")
        data = recv_data(client)
        if data is None:
            print(f"Không nhận được gói tin {i+1}")
            client.close()
            exit()
        try:
            goi = json.loads(data.decode())
            send_ack(client)
            goi_tin_nhan.append(goi)
        except json.JSONDecodeError as e:
            print(f"Lỗi xử lý gói tin {i+1}: {e}")
            client.close()
            exit()

    file_dau_ra = "Mp3_Mau_reconstructed.mp3"
    with open(file_dau_ra, "wb") as f:
        for i, goi in enumerate(goi_tin_nhan, 1):
            try:
                iv = base64.b64decode(goi["iv"])
                ban_ma = base64.b64decode(goi["cipher"])
                hash_doan = goi["hash"]
                chu_ky_doan = base64.b64decode(goi["sig"])

                hash_obj = SHA512.new(iv + ban_ma)
                pkcs1_15.new(khoa_cong_khai_nguoi_gui).verify(hash_obj, chu_ky_doan)
                print(f"Xác minh chữ ký đoạn {i} thành công!")

                if hash_obj.hexdigest() != hash_doan:
                    print(f"Kiểm tra hash đoạn {i} thất bại!")
                    client.close()
                    exit()
                print(f"Kiểm tra hash đoạn {i} thành công!")

                giai_ma_3des = DES3.new(khoa_phien, DES3.MODE_CBC, iv)
                doan = giai_ma_3des.decrypt(ban_ma).rstrip(b"\x00")
                f.write(doan)
            except (ValueError, KeyError) as e:
                print(f"Lỗi xử lý đoạn {i}: {e}")
                client.close()
                exit()

    print(f"Tái tạo file thành công: {file_dau_ra}")

except Exception as e:
    print(f"Lỗi người nhận: {e}")
finally:
    client.close()