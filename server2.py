import socket
import json
import hashlib
import threading
import pymysql
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import logging
import gnupg

logging.basicConfig(level=logging.DEBUG)

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.exit_flag = False

        # self.server_address = server_address
        self.gpg = gnupg.GPG()
        self.server_key_id = None
        self.server_public_key_path = "server_public_key.asc"  # اسم ملف مفتاح السيرفر العام
        self.server_private_key_path = "server_private_key.asc"  # اسم ملف مفتاح السيرفر الخاص
        self.server_public_key = None
        self.server_private_key = None
        self.client_public_key = None

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logging.info(f"Server is listening on {self.host}:{self.port}...")





    def generate_keys(self):
        # إنشاء مفتاح للسيرفر
        passphrase = "ffffffff"
        input_data = self.gpg.gen_key_input(key_type='RSA', key_length=2048 ,passphrase=passphrase)
        key = self.gpg.gen_key(input_data)

        # حفظ معرف المفتاح (العام) في الكائن
        self.server_key_id = key.fingerprint

        self.server_public_key = self.gpg.export_keys(key.fingerprint, False)
        self.server_private_key = self.gpg.export_keys(key.fingerprint, True, passphrase=passphrase)

        # حفظ المفتاح العام في ملف
        with open(self.server_public_key_path, 'w') as server_public_key_file:
            server_public_key_file.write(self.server_public_key)

        # حفظ المفتاح الخاص في ملف
        with open(self.server_private_key_path, 'w') as server_private_key_file:
            server_private_key_file.write(self.server_private_key)

        return self.server_key_id

    # def receive_public_key(self, client_socket):
    #     # استقبال مفتاح العميل العام من العميل
    #     data = client_socket.recv(4096)
    #     client_public_key_content = json.loads(data.decode('utf-8'))["public_key"]
    #     self.client_public_key = client_public_key_content
    #     print("Received client public key.")
    #
    # def send_public_key(self, client_socket):
    #     # إرسال مفتاح السيرفر العام إلى العميل
    #     server_public_key_content = "Server's public key content"  # يجب استبداله بالمفتاح العام الفعلي
    #     response = {"server_public_key": server_public_key_content}
    #     response_data = json.dumps(response).encode('utf-8')
    #     client_socket.send(response_data)
    #     print("Sent server public key to client.")

    def perform_handshake(self, client_socket):
        try:
            self.generate_keys()

            # استقبال مفتاح العميل العام من العميل
            data = client_socket.recv(4096)
            print(f"data: {data}")
            client_public_key_content = json.loads(data.decode('utf-8')).get("public_key")
            if client_public_key_content is not None:
                self.client_public_key = client_public_key_content
                print("Received client public key.")
            else:
                print("Error: Client public key is None.")
                return False

            #
            # الخطوة 2: إرسال مفتاح السيرفر العام

            with open(self.server_public_key_path, 'r') as public_key_file:
                server_public_key_content = public_key_file.read()
            # server_public_key_content = "Server's public key content"  # يجب استبداله بالمفتاح العام الفعلي
            response = {"server_public_key": server_public_key_content}
            response_data = json.dumps(response).encode('utf-8')
            client_socket.send(response_data)
            print("Sent server public key to client.")

            # # الخطوة 3: استقبال مفتاح العميل العام مرة أخرى (للتأكيد)
            # data = client_socket.recv(4096)
            # client_public_key_content = json.loads(data.decode('utf-8'))["public_key"]
            # self.client_public_key = client_public_key_content
            # print("Received client public key.")


            # يمكن أن تتضمن المرحلة الأخيرة تأكيدًا على نجاح عملية Handshaking
            handshake_successful = True

            return handshake_successful

        except Exception as e:
            print(f"Error during handshake: {e}")
            return False

    def start_server(self):
        while not self.exit_flag:
            try:
                client, addr = self.server_socket.accept()
                logging.info(f"Accepted connection from {addr}")

                client_handler = threading.Thread(target=self.perform_handshake, args=(client,))
                client_handler.start()
            except Exception as e:
                logging.error(f"Error accepting client connection: {e}")

        logging.info("Exiting the server.")
        self.server_socket.close()

if __name__ == "__main__":
    try:
        server = Server('0.0.0.0', 12352)
        # server.generate_keys()
        server.start_server()
    except KeyboardInterrupt:
        server.exit_flag = True  # Set the flag when KeyboardInterrupt (Ctrl+C) is detected
