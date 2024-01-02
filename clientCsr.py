import random

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding


class ClientCsr:
    def __init__(self):
        self.sprivate_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def generate_csr1(self, name, national_id):
        # تعريف معلومات الـ Subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'SY'),   # اسم الدولة يمكن تعديله وفقًا لمتطلباتك
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Damas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Damas'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Damascus University'),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, national_id),  # إضافة رقم الهوية الوطنية
        ])

        # إعداد معلومات الـ CSR
        csr_builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.sprivate_key.public_key()),
                critical=False,
            )
        )

        # إنشاء معلومات الـ CSR
        csr = csr_builder.sign(
            private_key=self.sprivate_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        # تحويل الـ CSR إلى تسلسل من البايتات
        csr_bytes = csr.public_bytes(serialization.Encoding.PEM)

        return csr_bytes


    def send_csr_to_ca1(self, ca, cname, national_id):
        # إرسال CSR إلى الـ CA
        csr = self.generate_csr1(cname, national_id)
        signature = ca.sign_certificate1(csr, cname)
        return csr, signature

    def verify_certificate1(self, signature, cca_public_key, csr):
        # التحقق من التوقيع باستخدام مفتاح الـ CA العام
        try:
            cca_public_key.verify(
                signature,
                csr,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            # print("The certificate has been verified successfully")
            return signature

        except Exception as e:
            print(f"Certificate verification failed: {e}")
