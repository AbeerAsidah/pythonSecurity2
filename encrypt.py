from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import hashlib
import os



def generate_key(national_id):
    # Convert the national ID to a key
    return hashlib.sha256(national_id.encode()).digest()

def encrypt_data(data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad_data(data)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return b64encode(ciphertext)

def decrypt_data(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(b64decode(ciphertext)) + decryptor.finalize()
    return remove_padding(decrypted_data)

def pad_data(data):
    block_size = 16
    padding = block_size - (len(data) % block_size)
    return data + bytes([padding] * padding)

def remove_padding(data):
    padding = data[-1]
    return data[:-padding]

def generate_symmetric_key():
    # You can generate the key in a secure way
    # Here, a key is generated randomly for illustrative purposes,
    # but it's recommended to generate a key securely in production
    return b64encode(os.urandom(32))
