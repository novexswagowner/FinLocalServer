import sys
from cryptography.fernet import Fernet

def encrypt_file(input_path, output_path, key_path='key.key'):
    with open(key_path, 'rb') as kf:
        key = kf.read()
    fernet = Fernet(key)

    with open(input_path, 'rb') as f:
        data = f.read()
    encrypted = fernet.encrypt(data)

    with open(output_path, 'wb') as ef:
        ef.write(encrypted)
    print(f"Файл зашифрован: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python encrypt_file.py <входной_файл> <выходной_файл>")
    else:
        encrypt_file(sys.argv[1], sys.argv[2])
