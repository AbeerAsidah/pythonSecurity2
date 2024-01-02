import gnupg
import socket
import json
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import logging


class Doctor:
    def __init__(self, client_id,server_address=('127.0.0.1', 12352)):
        self.server_address = server_address
        self.gpg = gnupg.GPG()
        self.client_id = client_id
        self.client_key_id = None
        self.client_public_key_path = f"{client_id}_public_key.asc"  # اسم ملف المفتاح العام
        self.client_private_key_path = f"{client_id}_private_key.asc"  # اسم ملف المفتاح الخاص
        self.server_public_key = None
        self.client_public_key = None
        self.client_private_key = None

    def generate_keys(self):
        # print(f"enter passphrase")
        passphrase = input("Enter passphrase for the private key: ")

        # إنشاء مفتاح للعميل
        input_data = self.gpg.gen_key_input(key_type='RSA', key_length=2048, passphrase=passphrase)
        key = self.gpg.gen_key(input_data)

        # حفظ معرف المفتاح (العام) في الكائن
        self.client_key_id = key.fingerprint

        # الحصول على المفتاح العام والخاص
        self.client_public_key = self.gpg.export_keys(key.fingerprint, False)
        self.client_private_key = self.gpg.export_keys(key.fingerprint, True, passphrase=passphrase)

        # حفظ المفتاح العام في ملف
        with open(self.client_public_key_path, 'w') as public_key_file:
            public_key_file.write(self.client_public_key)

        # حفظ المفتاح الخاص في ملف
        with open(self.client_private_key_path, 'w') as private_key_file:
            private_key_file.write(self.client_private_key)

        return self.client_key_id

    def send_public_key_to_server(self):
        # قراءة محتوى مفتاح العميل العام من الملف
        with open(self.client_public_key_path, 'r') as public_key_file:
            client_public_key_content = public_key_file.read()

        # إرسال محتوى مفتاح العميل العام إلى السيرفر
        request = {
            "action": "send_public_key",
            "public_key": client_public_key_content
        }

        # توسيع الكود لإرسال الطلب
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(self.server_address)

        try:
            response_data = json.dumps(request).encode('utf-8')
            client.send(response_data)
            print(f"h : {self.client_public_key}")
            print("Sent client public key to server.")

            # الخطوة 2: استقبال مفتاح السيرفر العام من السيرفر
            data = client.recv(4096)
            print(f"data : {data}")
            server_public_key_content = json.loads(data.decode('utf-8')).get("server_public_key")
            # if server_public_key_content is not None:
            self.server_public_key = server_public_key_content
            print("Received server public key.")
            # else:
            #     print("Error: server public key is None.")
            #     return False

        except Exception as e:
            print(f"Error sending/receiving data: {e}")

        finally:
            client.close()

    def perform_handshake(self):
        try:
            # الخطوة 1: إرسال مفتاح العميل العام للسيرفر
            self.send_public_key_to_server()

            # يمكن أن تتضمن المرحلة الأخيرة تأكيدًا على نجاح عملية Handshaking
            handshake_successful = True

            return handshake_successful

        except Exception as e:
            print(f"Error during handshake: {e}")
            return False
