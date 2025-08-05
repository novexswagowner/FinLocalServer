import socket
import threading
import time

HOST = 'localhost'
PORT = 12345

def client_task(message, delay=0):
    time.sleep(delay)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        sock.sendall(message.encode())
        response = sock.recv(1024).decode()
        print(f"[{message}] Ответ от сервера: {response}")
    except Exception as e:
        print(f"Ошибка клиента [{message}]: {e}")
    finally:
        sock.close()

messages = ['Привет', 'Как дела?', 'shutdown', '123', 'exit']
threads = []

for i, msg in enumerate(messages):
    t = threading.Thread(target=client_task, args=(msg, i * 0.5))
    t.start()
    threads.append(t)

for t in threads:
    t.join()
