import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding, hashes
import base64

#generate a key from a password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

#function to decrypt file
def decrypt_file(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(decrypted_data) + unpadder.finalize()

    return data

#main function for the receiver
def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)

    password = 'strongpassword'
    salt = b'secure_salt'
    key = generate_key(password, salt)

    print("Waiting for connection...")
    client_socket, address = server_socket.accept()
    print(f"Connection from {address} established.")

    #receive file name
    file_name = b""
    while True:
        char = client_socket.recv(1)
        if char == b'\0':
            break
        file_name += char
    file_name = file_name.decode()

    #receive encrypted file
    encrypted_data = b""
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        encrypted_data += data

    decrypted_data = decrypt_file(encrypted_data, key)

    #save the file in the same directory as the script
    script_directory = os.path.dirname(os.path.abspath(__file__))
    output_file_path = os.path.join(script_directory, file_name)

    with open(output_file_path, 'wb') as file:
        file.write(decrypted_data)

    print(f"File received and decrypted successfully. Saved to {output_file_path}")
    client_socket.close()
    server_socket.close()

if __name__ == '__main__':
    main()