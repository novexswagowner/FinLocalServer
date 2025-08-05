import socket
import threading
import datetime
import sys
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from os import urandom

HOST = 'localhost'
PORT = 12345
LOG_FILE = 'server_log.txt'

client_threads = []

# Загрузка DH-параметров из файла
with open("dh_params.pem", "rb") as f:
    dh_parameters = serialization.load_pem_parameters(f.read())

def log(message):
    print(message)
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.datetime.now()} - {message}\n")

def handle_client(conn, addr):
    log(f"Подключение от {addr}")
    try:
        server_private_key = dh_parameters.generate_private_key()
        server_public_key = server_private_key.public_key()

        client_pub_bytes = conn.recv(4096)
        client_public_key = serialization.load_pem_public_key(client_pub_bytes)

        server_pub_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.send(server_pub_bytes)

        shared_key = server_private_key.exchange(client_public_key)

        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)

        log("Ключ установлен")
        used_nonces = set()

        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                message_json = json.loads(data.decode())
                nonce = bytes.fromhex(message_json['nonce'])
                if message_json['nonce'] in used_nonces:
                    log("⚠️ Повторное сообщение отклонено.")
                    continue
                used_nonces.add(message_json['nonce'])

                ciphertext = bytes.fromhex(message_json['ciphertext'])
                aesgcm = AESGCM(key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()

                log(f"Сообщение от {addr}: {plaintext}")

                if plaintext == 'shutdown':
                    conn.send(encrypt_message("Сервер завершает работу.", key))
                    shutdown_server()
                else:
                    conn.send(encrypt_message(f"Эхо: {plaintext}", key))
            except Exception as e:
                log(f"Ошибка расшифровки: {e}")
                continue
    except Exception as e:
        log(f"Ошибка при работе с клиентом {addr}: {e}")
    finally:
        conn.close()

def encrypt_message(text, key):
    aesgcm = AESGCM(key)
    nonce = urandom(12)
    ciphertext = aesgcm.encrypt(nonce, text.encode(), None)
    return json.dumps({
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex()
    }).encode()

def shutdown_server():
    log("Остановка сервера...")
    server_socket.close()
    sys.exit(0)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((HOST, PORT))
server_socket.listen(5)
log("Сервер запущен и ожидает подключения...")

try:
    while True:
        conn, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        client_threads.append(thread)
except Exception as e:
    log(f"Ошибка основного цикла сервера: {e}")
finally:
    server_socket.close()
