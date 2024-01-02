from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

class DigitalSignature:
    def init(self):
        # Generate a new RSA key pair (private key and public key)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def sign_data(self, data):
        # Sign the data using the private key
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, data, signature, public_key):
        # Verify the signature using the public key
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True  # Signature is valid
        except Exception:
            return False  # Signature is invalid

# Example usage
if name == "main":
    # Create an instance of the DigitalSignature class
    digital_signature = DigitalSignature()

    # Data to be signed
    data_to_sign = b"Hello, this is some data."

    # Sign the data
    signature = digital_signature.sign_data(data_to_sign)

    # Verify the signature
    is_signature_valid = digital_signature.verify_signature(data_to_sign, signature, digital_signature.public_key)

    if is_signature_valid:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")