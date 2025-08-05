import socket
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from os import urandom

HOST = 'localhost'
PORT = 12345

# Загрузка DH-параметров из файла
with open("dh_params.pem", "rb") as f:
    dh_parameters = serialization.load_pem_parameters(f.read())

def encrypt_message(text, key):
    aesgcm = AESGCM(key)
    nonce = urandom(12)
    ciphertext = aesgcm.encrypt(nonce, text.encode(), None)
    return json.dumps({
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex()
    }).encode()

def decrypt_message(data, key):
    message_json = json.loads(data.decode())
    nonce = bytes.fromhex(message_json['nonce'])
    ciphertext = bytes.fromhex(message_json['ciphertext'])
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    private_key = dh_parameters.generate_private_key()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(public_bytes)

    server_pub_bytes = client_socket.recv(4096)
    server_public_key = serialization.load_pem_public_key(server_pub_bytes)

    shared_key = private_key.exchange(server_public_key)

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)

    print("Защищённое соединение установлено.")

    while True:
        msg = input("Введите сообщение (или 'exit'): ")
        if msg.strip().lower() == 'exit':
            break
        client_socket.send(encrypt_message(msg, key))
        response = client_socket.recv(4096)
        print("Ответ сервера:", decrypt_message(response, key))

except Exception as e:
    print("Ошибка клиента:", e)
finally:
    client_socket.close()
