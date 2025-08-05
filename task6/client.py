import socket

HOST = 'localhost'
PORT = 12345

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))

        while True:
            message = input("Введите сообщение (или 'exit' для выхода): ").strip()
            if message == 'exit':
                print("Завершение клиента...")
                break
            client_socket.send(message.encode())
            response = client_socket.recv(1024).decode()
            print(f"Ответ от сервера: {response}")

except ConnectionRefusedError:
    print("Невозможно подключиться к серверу.")
except Exception as e:
    print(f"Ошибка клиента: {e}")
