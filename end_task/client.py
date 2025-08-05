import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import base64

HOST = '127.0.0.1'
TCP_PORT = 12345
UDP_PORT = 12346

def derive_fernet_key(shared_key: bytes) -> Fernet:
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return Fernet(base64.urlsafe_b64encode(derived))

def tcp_client():
    print("[КЛИЕНТ] TCP режим")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, TCP_PORT))

    try:
        param_data = b""
        while b"-----END DH PARAMETERS-----" not in param_data:
            param_data += sock.recv(1024)
        
        print(f"[КЛИЕНТ] Получены параметры DH от сервера: {param_data.decode(errors='ignore')}")

        parameters = serialization.load_pem_parameters(param_data, backend=default_backend())

        peer_pub_data = b""
        while b"-----END PUBLIC KEY-----" not in peer_pub_data:
            peer_pub_data += sock.recv(1024)

        print(f"[КЛИЕНТ] Получен публичный ключ сервера: {peer_pub_data.decode(errors='ignore')}")
        server_pub_key = serialization.load_pem_public_key(peer_pub_data, backend=default_backend())

        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        pub_bytes = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        sock.sendall(pub_bytes)

        shared = private_key.exchange(server_pub_key)
        print(f"[КЛИЕНТ] Общий ключ вычислен: {shared.hex()}")
        fernet = derive_fernet_key(shared)

        message = input("Введите сообщение: ")
        sock.sendall(fernet.encrypt(message.encode()))

        response = sock.recv(4096)
        print("Ответ от сервера:", fernet.decrypt(response).decode())
    except Exception as e:
        print(f"[КЛИЕНТ] Ошибка: {e}")
    finally:
        sock.close()

def udp_client():
    print("[КЛИЕНТ] UDP режим")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.sendto(b"GET_DH_PARAMETERS", (HOST, UDP_PORT))
        param_data, _ = sock.recvfrom(4096)
        parameters = serialization.load_pem_parameters(param_data, backend=default_backend())

        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        pub_bytes = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        sock.sendto(pub_bytes, (HOST, UDP_PORT))

        server_pub_data, _ = sock.recvfrom(4096)
        server_key = serialization.load_pem_public_key(server_pub_data, backend=default_backend())

        shared = private_key.exchange(server_key)
        fernet = derive_fernet_key(shared)

        message = input("Введите сообщение: ")
        sock.sendto(fernet.encrypt(message.encode()), (HOST, UDP_PORT))

        response, _ = sock.recvfrom(4096)
        print("Ответ от сервера:", fernet.decrypt(response).decode())
    except Exception as e:
        print(f"[КЛИЕНТ] Ошибка: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    protocol = input("Выберите протокол [tcp/udp]: ").strip().lower()
    if protocol == "tcp":
        tcp_client()
    elif protocol == "udp":
        udp_client()
    else:
        print("Ошибка: неизвестный протокол.")
