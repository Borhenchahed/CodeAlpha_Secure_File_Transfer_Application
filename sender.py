import socket
import os
import tkinter as tk
from tkinter import filedialog, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding, hashes
import base64

#function to generate a key from a password
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

#function to encrypt the file
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

#function to send the encrypted file
def send_file(file_path, ip, key):
    encrypted_data = encrypt_file(file_path, key)
    file_name = os.path.basename(file_path)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ip, 12345))

    #send the file name
    client_socket.sendall(file_name.encode() + b'\0')

    #send the encrypted file data
    client_socket.sendall(encrypted_data)
    client_socket.close()
    print(f"File {file_name} sent successfully.")

def main():
    root = tk.Tk()
    root.withdraw()

    #ask for file path
    file_path = filedialog.askopenfilename()
    if not file_path:
        print("No file selected.")
        return

    #ask for IP address
    ip = simpledialog.askstring("Input", "Enter the receiver's IP address:")
    if not ip:
        print("No IP address entered.")
        return

    password = 'strongpassword'
    salt = b'secure_salt'
    key = generate_key(password, salt)

    send_file(file_path, ip, key)

if __name__ == '__main__':
    main()