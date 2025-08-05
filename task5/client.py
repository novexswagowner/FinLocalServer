import socket

SERVER_IP = '127.0.0.1'
SERVER_PORT = 12345
BUFFER_SIZE = 1024

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    while True:
        message = input("Введите сообщение (или 'exit' для выхода): ")
        client_socket.sendto(message.encode(), (SERVER_IP, SERVER_PORT))
        if message.lower() == 'exit':
            print("Сеанс завершён.")
            break

        data, _ = client_socket.recvfrom(BUFFER_SIZE)
        print(f"Ответ от сервера: {data.decode()}")

except Exception as e:
    print(f"Ошибка клиента: {e}")
finally:
    client_socket.close()
