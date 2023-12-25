from secrets import token_bytes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FORMAT = 'utf-8'
BLOCK_SIZE = 16


class ECDH:
    def __init__(self):
        self.ECDH = ec.generate_private_key(ec.SECP384R1(), default_backend())  # PRIVATE KEY 384 BIT LONG
        self.public_key = self.ECDH.public_key()  # PUBLIC KEY : CHANGE BETWEEN CLIENTS

    def encrypt(self, public_key, plaintext):
        """
        IV = 16 bytes
        SALT = 16 bytes
        Shared key = 48 bytes
        Derived key = 32 bytes

        AES block size = 128 bits
        AES block size = 16 bytes
        AES key = 256 bits
        AES key = 32 bytes

        Padder = 128 bits
        Padder = 16 bytes

        Ciphertext = IV + SALT + MSG

        :param public_key: another client public key
        :param plaintext: a text to be encrypted
        :return: encrypted ciphertext
        """
        IV = token_bytes(16)  # INITIALIZING VECTOR 16 BYTES : SEND WITH CIPHER TEXT
        SALT = token_bytes(16)  # SALT FOR DERIVATION A SHARED KEY
        shared_key = self.ECDH.exchange(ec.ECDH(), public_key)  # GEN SHARED KEY FROM ANOTHER CLIENT PUBLIC KEY

        derived_key = HKDF(  # DERIVE KEY FOR MORE STRENGTH
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            info=None
        ).derive(shared_key)

        encryptor = Cipher(
            algorithms.AES(derived_key),
            modes.CBC(IV)
        ).encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode(FORMAT)) + padder.finalize()

        return IV + SALT + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, public_key, ciphertext):
        IV = ciphertext[:16]
        SALT = ciphertext[16:32]
        ciphertext = ciphertext[32:]

        shared_key = self.ECDH.exchange(ec.ECDH(), public_key)  # GEN SHARED KEY FROM ANOTHER CLIENT PUBLIC KEY

        derived_key = HKDF(  # DERIVE KEY FOR MORE STRENGTH
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            info=None
        ).derive(shared_key)

        decryptor = Cipher(
            algorithms.AES(derived_key),
            modes.CBC(IV)
        ).decryptor()

        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()

        return unpadder.update(decrypted_data) + unpadder.finalize()

    def serialize_public(self):
        serialized_public = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return serialized_public

    def unserialize_public(self, public_key):
        loaded_public_key = serialization.load_pem_public_key(
            public_key,
        )
        return loaded_public_key
