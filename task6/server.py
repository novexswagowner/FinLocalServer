import socket
import selectors
import types
import sys
import traceback
import datetime

sel = selectors.DefaultSelector()
LOG_FILE = 'tcp_server_log.txt'

def log(message):
    print(message)
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.datetime.now()} - {message}\n")

def accept_wrapper(sock):
    conn, addr = sock.accept()
    log(f"Подключение от {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    sel.register(conn, selectors.EVENT_READ, data=data)

def send_echo(key, mask):
    sock = key.fileobj
    data = key.data
    try:
        recv_data = sock.recv(1024)
        if recv_data:
            message = recv_data.decode().strip()
            log(f"Сообщение от {data.addr}: {message}")

            if message == "shutdown":
                log("Команда shutdown получена. Завершение сервера.")
                sock.send(bytes("Сервер завершает работу.", "utf-8"))
                sel.unregister(sock)
                sock.close()
                shutdown_server()
                return

            sock.send(f"Эхо: {message}".encode())
        else:
            log(f"Клиент {data.addr} отключился.")
            sel.unregister(sock)
            sock.close()
    except Exception as e:
        log(f"Ошибка при обработке {data.addr}: {e}")
        try:
            sel.unregister(sock)
        except Exception:
            pass
        sock.close()

def shutdown_server():
    log("Закрытие всех подключений...")
    for key in list(sel.get_map().values()):
        try:
            sel.unregister(key.fileobj)
            key.fileobj.close()
        except Exception:
            pass
    sel.close()
    log("Сервер остановлен.")
    sys.exit(0)

host, port = 'localhost', 12345
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lsock.bind((host, port))
lsock.listen()
log(f"Сервер запущен на {host}:{port}")
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

try:
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                send_echo(key, mask)
except KeyboardInterrupt:
    log("Остановка по Ctrl+C")
    shutdown_server()
except Exception as e:
    log(f"Фатальная ошибка: {traceback.format_exc()}")
    shutdown_server()
