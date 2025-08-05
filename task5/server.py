import socket
import sys

SERVER_IP = '0.0.0.0'
SERVER_PORT = 12345
BUFFER_SIZE = 1024

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((SERVER_IP, SERVER_PORT))

print(f"UDP сервер запущен на {SERVER_IP}:{SERVER_PORT}")

try:
    while True:
        data, addr = server_socket.recvfrom(BUFFER_SIZE)
        message = data.decode().strip()
        print(f"Получено от {addr}: {message}")

        if message.lower() == 'exit':
            print("Команда завершения получена. Остановка сервера.")
            server_socket.sendto("Сервер завершает работу.".encode(), addr)
            break

        response = f"Эхо: {message}"
        server_socket.sendto(response.encode(), addr)

except Exception as e:
    print(f"Ошибка сервера: {e}")
finally:
    server_socket.close()
    print("Сервер остановлен.")
