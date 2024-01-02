import random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

#Ca
class UniversityCertificateAuthority:
    def __init__(self):
        # يمكنك توليد مفتاح لـ CA هنا
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def generate_challenge(self):
        # يولد تحدي عشوائي لكل طلب
        return random.randint(1000, 9999)

    def request_doctor_challenge(self):
        # يقوم الـ CA بتوليد تحدي وإرساله للدكتور
        challenge = self.generate_challenge()
        print(f"CA: challenge {challenge}")
        return challenge

    def verify_doctor_identity(self, received_challenge, doctor_solution):
        # يتحقق الـ CA من حلا الدكتور للتحدي
        return received_challenge == doctor_solution

    def sign_certificate(self, csr, doctor_name):
        # يقوم الـ CA بالتحقق من هوية الدكتور وارتباطه بالـ Public Key
        # عن طريق طلب تحدي وحله من الدكتور قبل توقيع الـ CSR
        challenge = self.request_doctor_challenge()
        doctor_solution = input("Please enter a solution to the challenge: ")
        if self.verify_doctor_identity(challenge, int(doctor_solution)):
            # في حالة تحقق الهوية، يتم توقيع الـ CSR
            signature = self.ca_private_key.sign(
                csr,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print(f"{doctor_name} identity has been verified and the certificate signed.")
            return signature
        else:
            print("Client's certificate verification failed.")
            return None