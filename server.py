import socket
import json
import hashlib
import threading
import pymysql
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
# import os
# import secrets
import logging

logging.basicConfig(level=logging.DEBUG)

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.exit_flag = False

        # Database configuration
        self.db_config = {
            'host': 'localhost',
            'user': 'abeer2222',  # Replace with your MySQL username
            'password': '12aa12aa',  # Replace with your MySQL password
            'database': 'pythonsecurity'
        }

        # Establish a connection to the database
        self.db_connection = pymysql.connect(**self.db_config)
        self.db_cursor = self.db_connection.cursor()

        # Server initialization
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logging.info(f"Server is listening on {self.host}:{self.port}...")

    def pad_data(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')

        block_size = 16
        padding = block_size - (len(data) % block_size)
        return data + bytes([padding] * padding)

    def remove_padding(self, data):
        padding = data[-1]
        return data[:-padding]

    def encrypt_data(self, data, shared_key):
        try:
            if shared_key is not None:
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
                cipher = Cipher(algorithms.AES(shared_key), modes.CFB(b'\x00' * 16), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

                logging.debug(f'Encrypted data: {base64.b64encode(encrypted_data).decode("utf-8")}')

                return base64.b64encode(encrypted_data).decode('utf-8')
            else:
                logging.error("Shared key is None. Cannot encrypt data.")
                return None
        except Exception as e:
            logging.error(f'Encryption error: {e}')
            return None

    def decrypt_data(self, encrypted_data, shared_key):
        try:
            if shared_key is not None:
                cipher = Cipher(algorithms.AES(shared_key), modes.CFB(b'\x00' * 16), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(base64.b64decode(encrypted_data)) + decryptor.finalize()

                if decrypted_data is not None:
                    decoded_data = self.remove_padding(decrypted_data)
                    if decoded_data is not None:
                        logging.debug(f'Decrypted data: {decoded_data.decode("utf-8")}')
                        return decoded_data.decode('utf-8')
                    else:
                        logging.error("Decoding error: remove_padding returned None")
                        return None
                else:
                    logging.error("Decryption error: decrypted_data is None")
                    return None
            else:
                logging.error("Shared key is None. Cannot decrypt data.")
                return None
        except Exception as e:
            logging.error(f'Decryption error: {e}')
            return None

    def hash_password(self, password):
        if isinstance(password, bytes):
            password_bytes = password
        elif isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            raise ValueError("Password must be either str or bytes")

        hashed_password = hashlib.sha256(password_bytes).hexdigest()
        return hashed_password

    def generate_key(self, national_id):
        return hashlib.sha256(national_id.encode()).digest()

    def handle_client(self, client_socket):
        try:
            request = client_socket.recv(4096).decode('utf-8')
            logging.debug(f"Received request: {request}")
            request_data = json.loads(request)
            shared_key_str = request_data.get("shared_key", "")
            shared_key = base64.b64decode(shared_key_str)

            if "action" not in request_data:
                # if "action" not in request_data or "username" not in request_data or "password" not in request_data:

                response = {"status": "failure", "message": "Invalid request format."}
            else:
                if request_data["action"] == "login":
                    username = request_data["username"]
                    encrypted_password = request_data["password"]

                    decrypted_password = self.decrypt_data(encrypted_password, shared_key)

                    if len(username) < 8 or len(decrypted_password) < 8:
                        response = {"status": "failure", "message": "Invalid input length."}
                    else:

                        self.db_cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
                        result = self.db_cursor.fetchone()

                        if result:
                            stored_password = result[0]
                            if decrypted_password and self.verify_password(decrypted_password, stored_password):
                                response = {"status": "success", "message": "Login successful!"}
                            else:
                                response = {"status": "failure", "message": "Invalid credentials."}
                        else:
                            response = {"status": "failure",
                                        "message": "Username not found. Do you want to create an account?"}

                elif request_data["action"] == "register":
                    username = request_data["username"]
                    national_id = request_data.get("national_id", None)
                    decrypted_password = self.decrypt_data(request_data["password"], shared_key)
                    print(f"Decrypted password: {request_data["username"]}")
                    if len(username) < 8 or len(decrypted_password) < 8 or (national_id and len(national_id) < 10):
                        response = {"status": "failure", "message": "Invalid input length."}

                    else:

                        # Check if the username already exists
                        self.db_cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
                        username_count = self.db_cursor.fetchone()[0]

                        # Check if the national ID already exists
                        self.db_cursor.execute("SELECT COUNT(*) FROM users WHERE national_id = %s", (national_id,))
                        national_id_count = self.db_cursor.fetchone()[0]

                        if username_count > 0 or national_id_count > 0:
                            # Either username or national ID is taken
                            response = {"status": "failure",
                                        "message": "Username or National ID already exists. Do you want to exit or enter new values?"}
                        else:
                            if decrypted_password and national_id:
                                hashed_password = self.hash_password(decrypted_password)
                                self.db_cursor.execute(
                                    "INSERT INTO users (username, password, national_id, registration_time) VALUES (%s, %s, %s, %s)",
                                    (username, hashed_password, national_id, None))
                                self.db_connection.commit()
                                response = {"status": "success", "message": "Account created successfully!"}
                            else:
                                response = {"status": "failure", "message": "Invalid password."}

                elif request_data["action"] == "add_additional_info":
                    national_id = request_data.get("national_id", "")
                    phone_number = self.decrypt_data(request_data["phone_number"], shared_key)
                    mobile_number = self.decrypt_data(request_data["mobile_number"], shared_key)
                    address = self.decrypt_data(request_data["address"], shared_key)
                    print(f"Error sending/شى data:")
                    query = "UPDATE users SET phone_number = %s, mobile_number = %s, address = %s " \
                            "WHERE national_id = %s"

                    data = (phone_number, mobile_number, address, national_id)

                    self.db_cursor.execute(query, data)
                    self.db_connection.commit()

                    response = {
                        "status": "success",
                        "message": "Additional information added successfully."
                        # "allow_additional_info": True  # Adjust this based on your logic
                    }

                else:
                    response = {"status": "failure", "message": "Invalid action."}

            encrypted_response = self.encrypt_data(json.dumps(response), shared_key)
            client_socket.send(encrypted_response.encode('utf-8'))

        except Exception as e:
            logging.error(f"Error handling client request: {e}")
        finally:
            if 'db_cursor' in locals():
                self.db_cursor.close()

            if 'db_connection' in locals() and self.db_connection.open:
                self.db_connection.close()
                logging.info("Database connection closed.")
            client_socket.close()

    def verify_password(self, input_password, stored_password):
        return self.hash_password(input_password) == stored_password

    def start_server(self):
        while not self.exit_flag:
            try:
                client, addr = self.server_socket.accept()
                logging.info(f"Accepted connection from {addr}")

                client_handler = threading.Thread(target=self.handle_client, args=(client,))
                client_handler.start()
            except Exception as e:
                logging.error(f"Error accepting client connection: {e}")

        logging.info("Exiting the server.")
        self.server_socket.close()

if __name__ == "__main__":
    try:
        server = Server('0.0.0.0', 12356)
        server.start_server()
    except KeyboardInterrupt:
        server.exit_flag = True  # Set the flag when KeyboardInterrupt (Ctrl+C) is detected
