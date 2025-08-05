from cryptography.fernet import Fernet

def generate_and_save_key(filename='key.key'):
    key = Fernet.generate_key()
    with open(filename, 'wb') as f:
        f.write(key)
    print(f"Ключ сохранён в {filename}")

if __name__ == "__main__":
    generate_and_save_key()
