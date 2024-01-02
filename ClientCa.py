import random

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

#Ca
class ClientCa:
    def __init__(self):
        # يمكنك توليد مفتاح لـ CA هنا
        self.cca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def generate_challenge1(self):
        # يولد تحدي عشوائي لكل طلب
        return random.randint(1000, 9999)

    def request_doctor_challenge1(self):
        # يقوم الـ CA بتوليد تحدي وإرساله للدكتور
        challenge = self.generate_challenge1()
        print(f"CA: challenge {challenge}")
        return challenge

    def verify_doctor_identity1(self, received_challenge, doctor_solution):
        # يتحقق الـ CA من حلا الدكتور للتحدي
        return received_challenge == doctor_solution

    def sign_certificate1(self, csr, cname):
        # يقوم الـ CA بالتحقق من هوية الدكتور وارتباطه بالـ Public Key
        # عن طريق طلب تحدي وحله من الدكتور قبل توقيع الـ CSR
        challenge = self.request_doctor_challenge1()
        doctor_solution = input("Please enter a solution to the challenge: ")
        if self.verify_doctor_identity1(challenge, int(doctor_solution)):
            # في حالة تحقق الهوية، يتم توقيع الـ CSR
            signature = self.cca_private_key.sign(
                csr,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            # print(f"{cname} identity has been verified and the certificate signed.")
            return signature
        else:
            print("Client's certificate verification failed.")
            return None