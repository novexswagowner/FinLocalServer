import socket
import threading
import datetime
import sys
from cryptography.fernet import Fernet

HOST = 'localhost'
PORT = 12345
LOG_FILE = 'server_log.txt'

with open("key.key", "rb") as f:
    key = f.read()

fernet = Fernet(key)

def log(message):
    print(message)
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.datetime.now()} - {message}\n")

def handle_client(conn, addr):
    log(f"Подключение от {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                message = fernet.decrypt(data).decode()
                log(f"Сообщение от {addr}: {message}")
                if message.strip() == 'shutdown':
                    conn.send(fernet.encrypt("Сервер завершает работу.".encode()))
                    conn.close()
                    shutdown_server()
                    return
                response = f"Эхо: {message}"
                conn.send(fernet.encrypt(response.encode()))
            except Exception as e:
                log(f"Ошибка расшифровки: {e}")
    except Exception as e:
        log(f"Ошибка при работе с клиентом {addr}: {e}")
    finally:
        conn.close()

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
except Exception as e:
    log(f"Ошибка основного цикла сервера: {e}")
finally:
    server_socket.close()
