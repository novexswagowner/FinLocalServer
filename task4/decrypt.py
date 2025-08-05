import sys
from cryptography.fernet import Fernet

def decrypt_file(input_path, output_path, key_path='key.key'):
    with open(key_path, 'rb') as kf:
        key = kf.read()
    fernet = Fernet(key)

    with open(input_path, 'rb') as f:
        encrypted = f.read()
    decrypted = fernet.decrypt(encrypted)

    with open(output_path, 'wb') as df:
        df.write(decrypted)
    print(f"Файл расшифрован: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python decrypt_file.py <зашифрованный_файл> <выходной_файл>")
    else:
        decrypt_file(sys.argv[1], sys.argv[2])
