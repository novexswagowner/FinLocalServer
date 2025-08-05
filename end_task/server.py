import socket
import threading
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import base64

HOST = '127.0.0.1'
TCP_PORT = 12345
UDP_PORT = 12346

parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def derive_fernet_key(shared_key: bytes) -> Fernet:
    """Функция для создания ключа Fernet из общего ключа."""
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return Fernet(base64.urlsafe_b64encode(derived))

def handle_tcp_client(conn, addr):
    print(f"[TCP] Клиент {addr} подключен")

    try:
        param_bytes = parameters.parameter_bytes(
            serialization.Encoding.PEM,
            serialization.ParameterFormat.PKCS3
        )
        conn.sendall(param_bytes)

        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        pub_bytes = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(pub_bytes)

        peer_pub = conn.recv(4096)
        print(f"[TCP] Получен публичный ключ клиента: {peer_pub.decode(errors='ignore')}")
        peer_key = serialization.load_pem_public_key(peer_pub, backend=default_backend())

        shared = private_key.exchange(peer_key)
        print(f"[TCP] Общий ключ вычислен: {shared.hex()}")
        fernet = derive_fernet_key(shared)

        encrypted = conn.recv(4096)
        message = fernet.decrypt(encrypted).decode()
        print(f"[TCP] {addr} → {message}")

        conn.sendall(fernet.encrypt(message.encode()))
    except Exception as e:
        print(f"[TCP] Ошибка при обработке клиента {addr}: {e}")
    finally:
        conn.close()
        print(f"[TCP] Клиент {addr} отключен")

def tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, TCP_PORT))
    server.listen()
    print(f"[TCP] Сервер слушает на {HOST}:{TCP_PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()

def udp_server():
    print(f"[UDP] Сервер слушает на {HOST}:{UDP_PORT}")
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((HOST, UDP_PORT))

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    param_bytes = parameters.parameter_bytes(
        serialization.Encoding.PEM,
        serialization.ParameterFormat.PKCS3
    )

    clients = {}

    while True:
        data, addr = udp_sock.recvfrom(4096)

        if data == b"GET_DH_PARAMETERS":
            udp_sock.sendto(param_bytes, addr)
            continue

        if addr not in clients:
            try:
                peer_key = serialization.load_pem_public_key(data, backend=default_backend())
                shared = private_key.exchange(peer_key)
                fernet = derive_fernet_key(shared)
                clients[addr] = fernet
                udp_sock.sendto(pub_bytes, addr)
                print(f"[UDP] Обмен ключами с {addr} завершен")
            except Exception as e:
                print(f"[UDP] Ошибка при установке ключа от {addr}: {e}")
            continue

        try:
            fernet = clients[addr]
            message = fernet.decrypt(data).decode()
            print(f"[UDP] {addr} → {message}")
            udp_sock.sendto(fernet.encrypt(message.encode()), addr)
        except Exception as e:
            print(f"[UDP] Ошибка обмена с {addr}: {e}")


if __name__ == "__main__":
    threading.Thread(target=tcp_server, daemon=True).start()
    udp_server()
