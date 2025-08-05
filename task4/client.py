import socket
from cryptography.fernet import Fernet

HOST = 'localhost'
PORT = 12345

with open("key.key", "rb") as f:
    key = f.read()

fernet = Fernet(key)

try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    while True:
        message = input("Введите сообщение (или 'exit'): ").strip()
        if message == 'exit':
            print("Завершение клиента...")
            break
        encrypted = fernet.encrypt(message.encode())
        client_socket.send(encrypted)
        response = client_socket.recv(4096)
        print("Ответ сервера:", fernet.decrypt(response).decode())
except Exception as e:
    print("Ошибка клиента:", e)
finally:
    client_socket.close()
