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
        self.public_key = None
        self.private_key = None

        # Database configuration
        self.db_config = {
            'host': 'localhost',
            'user': 'abeer2222',
            'password': '12aa12aa',
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
        block_size = 16
        padding_size = block_size - (len(data) % block_size)
        padding = bytes([padding_size] * padding_size)
        return data + padding

    def remove_padding(self, data):
        if not data:
            return b''  # Data may be empty

        padding = data[-1]

        if padding > len(data):
            return b''  # Incorrect padding for the data

        removed_padding_data = data[:-padding]
        return removed_padding_data




    def encrypt_data(self, data, shared_key):
        try:
            if shared_key is not None:
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
                cipher = Cipher(algorithms.AES(shared_key), modes.CFB(b'\x00' * 16), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                return base64.b64encode(encrypted_data).decode('utf-8')
            else:
                logging.error("Shared key is None. Cannot encrypt data.")
                return None
        except Exception as e:
            logging.error(f'Encryption error: {e}')
            return None





    def decrypt_data(self, encrypted_data, shared_key_str):
        try:
            print(f'hii_start_decrypt')
            if shared_key_str is not None:
                padding_needed = len(shared_key_str) % 4
                if padding_needed > 0:
                    # Add padding to make the length a multiple of 4
                    shared_key_str += '=' * (4 - padding_needed)

                if len(shared_key_str) not in {16, 24, 32}:
                    logging.error("Shared key length is not valid for AES.")
                    return None
                print(f'Shared key type: {type(shared_key_str)}, length: {len(shared_key_str)}')
                cipher = Cipher(algorithms.AES(shared_key_str), modes.CFB(b'\x00' * 16), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(base64.b64decode(encrypted_data)) + decryptor.finalize()
                print(f"Decrypted data (raw): {decrypted_data}")

                if decrypted_data is not None:
                    decoded_data = self.remove_padding(decrypted_data)
                    print(f"Decoded data: {decoded_data}")

                    if decoded_data is not None:

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



    def encrypt_shared_key(self,shared):
        try:
            gnupg_home = 'C:/Users/iStore/AppData/Roaming/gnupg'

            gpg = gnupg.GPG(gnupghome=gnupg_home)
            keys = gpg.list_keys()

            if keys:
                recipient = keys[0]['fingerprint']
                encrypted_shared_key = gpg.encrypt(str(shared), recipients=[recipient])
                return str(encrypted_shared_key)
            else:
                logging.error("No public key found in the specified GnuPG home directory.")
                return None

        except Exception as e:
            logging.error(f'Error during encryption: {e}')
            return None

    def decrypt_shared_key(self, encrypted_shared_key):
        try:
            gnupg_home = 'C:/Users/iStore/AppData/Roaming/gnupg'
            gpg = gnupg.GPG(gnupghome=gnupg_home)

            # Convert encrypted_shared_key to bytes if it's not already
            logging.debug(f'Before conversion: {encrypted_shared_key}')
            if not isinstance(encrypted_shared_key, bytes):
                encrypted_shared_key = encrypted_shared_key.encode('utf-8')
            logging.debug(f'After conversion: {encrypted_shared_key}')

            decrypted_shared_key = gpg.decrypt(encrypted_shared_key, passphrase='qwqw1111')

            # Extract sthe decrypted bytes
            decrypted_data = decrypted_shared_key.data
            return decrypted_data
        except Exception as e:
            logging.error(f'Error during decryption: {e}')
            return None

    def get_and_set_keys(self):
        try:
            gnupg_home = 'C:/Users/iStore/AppData/Roaming/gnupg'
            gpg = gnupg.GPG(gnupghome=gnupg_home)
            keys = gpg.list_keys()

            if keys:
                recipient_fingerprint = keys[0]['fingerprint']

                # Retrieve the public key
                public_key = gpg.export_keys(recipient_fingerprint)
                self.public_key = public_key

                # Retrieve the private key
                private_key = gpg.export_keys(recipient_fingerprint, secret=True)
                self.private_key = private_key

                print("Keys retrieved and set successfully.")
            else:
                print("No public key found in the specified GnuPG home directory.")

        except Exception as e:
            print(f'Error retrieving and setting keys: {e}')



    def verify_signature(self, signature):
        try:
            gnupg_home = 'C:/Users/iStore/AppData/Roaming/gnupg'

            gpg = gnupg.GPG(gnupghome=gnupg_home)
            # gpg.import_keys(self.private_key)  # استيراد المفتاح الخاص

            # قم بتشفير البيانات للتحقق منها باستخدام المفتاح العام
            verification = gpg.verify(signature)

            if verification.valid:
                return True
            else:
                logging.error(f'Signature verification failed: {verification.stderr}')
                return False

        except Exception as e:
            logging.error(f'Signature verification error: {e}')
            return False

    def handle_client(self, client_socket):
        try:
            request = client_socket.recv(4096).decode('utf-8')
            logging.debug(f"Received request: {request}")
            request_data = json.loads(request)
            shared_key_str = request_data.get("shared_key", "")
            shared_key = self.decrypt_shared_key(shared_key_str)


            if "action" not in request_data:
                # if "action" not in request_data or "username" not in request_data or "password" not in request_data:
                response = {"status": "failure", "message": "Invalid request format."}
            else:
                if request_data["action"] == "login":
                    username = self.decrypt_data(request_data["username"], shared_key)

                    encrypted_password = request_data["password"]
                    decrypted_password = self.decrypt_data(encrypted_password, shared_key)

                    if len(username) < 8 or len(decrypted_password) < 8:
                        response = {"status": "failure", "message": "Invalid input length."}
                    else:

                        self.db_cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
                        result = self.db_cursor.fetchone()
                        self.db_cursor.execute("SELECT type FROM users WHERE username = %s", (username,))
                        type = self.db_cursor.fetchone()
                        print(type[0])
                        if result:
                            stored_password = result[0]
                            if decrypted_password and self.verify_password(decrypted_password, stored_password):
                                response = {"status": "success", "message": "Login successful!","type": type[0]}
                            else:
                                response = {"status": "failure", "message": "Invalid credentials."}
                        else:
                            response = {"status": "failure",
                                        "message": "Username not found. Do you want to create an account?"}

                elif request_data["action"] == "register":
                    username = self.decrypt_data(request_data["username"], shared_key)

                    print(f"type: {request_data.get("type", None)}")
                    type2 = request_data.get("type", None)
                    type1 = self.decrypt_data(type2, shared_key)

                    national_id1 = request_data.get("national_id", None)
                    national_id = self.decrypt_data(national_id1, shared_key)

                    encrypted_password = request_data["password"]
                    decrypted_password = self.decrypt_data(encrypted_password, shared_key)

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
                                print(f'hbvsjkdla hello')
                                self.db_cursor.execute(
                                    "INSERT INTO users (username, password, national_id, registration_time, type ) VALUES (%s, %s, %s, %s, %s)",
                                    (username, hashed_password, national_id, None, type1))

                                self.db_connection.commit()
                                response = {"status": "success", "message": "Account created successfully!"}
                            else:
                                response = {"status": "failure", "message": "Invalid password."}

                elif request_data["action"] == "add_additional_info":
                    national_id = request_data.get("national_id", "")
                    phone_number = self.decrypt_data(request_data["phone_number"], shared_key)
                    mobile_number = self.decrypt_data(request_data["mobile_number"], shared_key)
                    address = self.decrypt_data(request_data["address"], shared_key)
                    query = "UPDATE users SET phone_number = %s, mobile_number = %s, address = %s " \
                            "WHERE national_id = %s"

                    data = (phone_number, mobile_number, address, national_id)

                    self.db_cursor.execute(query, data)
                    self.db_connection.commit()

                    response = {
                        "status": "success",
                        "message": "Additional information added successfully."
                    }

                elif request_data["action"] == "add_grades":
                    national_id = request_data.get("national_id", "")
                    print(f"national : {national_id}")

                    grades1 = request_data.get("grades", "")
                    print(f"grades : {grades1}")
                    grades = self.decrypt_data(grades1, shared_key)
                    print(f"decrypt_grades : {grades}")

                    sign_grades1 = request_data.get("sign_grades", "")
                    print(f"sign_grades : {sign_grades1}")
                    sign_grades = self.decrypt_data(sign_grades1, shared_key)
                    print(f"sign_grades : {sign_grades}")


                    grades1 = self.verify_signature(sign_grades)
                    print(grades1)
                    if grades1:
                        # Specify the columns to insert the data into
                        columns = ['student_name', 'subject', 'grade', 'doctor_name']

                        sql_query = f"INSERT INTO grades ({', '.join(columns)}) VALUES ({', '.join(['%s' for _ in columns])})"

                        try:
                            grades2 = json.loads(grades)

                            # تنفيذ الاستعلام لكل صف في القائمة
                            for grade in grades2:
                                values = [grade[column] for column in columns]
                                self.db_cursor.execute(sql_query, values)
                            # Execute the SQL query

                            self.db_connection.commit()  # Commit changes to the database

                            print("Grades successfully added to the grades table.")
                            response = {
                                "status": "success",
                                "message": "Grades stored successfully."
                            }
                        except Exception as e:
                            print(f"Error occurred while inserting data: {e}")
                            self.db_connection.rollback()
                            response = {
                                "status": "failure",
                                "message": "Error inserting data into the database."
                            }
                    else:
                        response = {
                            "status": "failure",
                            "message": "Invalid signature for grades."
                        }


                elif request_data["action"] == "add_projects":
                    national_id = request_data.get("national_id", "")
                    print(f"national : {national_id}")

                    projects1 = request_data.get("projects", "")
                    print(f"projects : {projects1}")
                    projects = self.decrypt_data(projects1, shared_key)
                    print(f"decrypt_projects : {projects}")


                        # Specify the columns to insert the data into
                    columns = ['project_name', 'project_description', 'completed', 'student_name']

                    sql_query = f"INSERT INTO projects ({', '.join(columns)}) VALUES ({', '.join(['%s' for _ in columns])})"

                    try:
                        projects2 = json.loads(projects)

                        # تنفيذ الاستعلام لكل صف في القائمة
                        for project in projects2:
                            values = [project[column] for column in columns]
                            self.db_cursor.execute(sql_query, values)
                        # Execute the SQL query

                        self.db_connection.commit()  # Commit changes to the database

                        print("Projects successfully added to the projects table.")
                        response = {
                            "status": "success",
                            "message": "Projects stored successfully."
                        }
                    except Exception as e:
                        print(f"Error occurred while inserting data: {e}")
                        self.db_connection.rollback()
                        response = {
                            "status": "failure",
                            "message": "Error inserting data into the database."
                        }

                elif request_data["action"] == "create_certificate":
                    username = request_data.get('student_name')
                    certificate = request_data.get('certificate')
                    print(f"certificate :{certificate}")
                    print("ll")
                    self.db_cursor.execute("SELECT certificate FROM client_certificate WHERE student_name = %s",
                                           (username,))
                    print("jj")
                    existing_certificate = None
                    existing_certificate_row = self.db_cursor.fetchone()

                    if existing_certificate_row is not None:
                        existing_certificate = existing_certificate_row[0]
                        print("gg", existing_certificate)

                    else:
                        print("No existing certificate found for the user:", username)


                    if existing_certificate_row is not None:
                        print("ff")
                        # If a certificate exists, send it back to the client
                        response = {"status": "success", "message": "Certificate already exists.",
                                    "certificate": existing_certificate.decode('utf-8')}
                        print(response)

                    else:
                        # If no certificate exists, store the new certificate in the database
                        # ... (existing code for storing signature in users table)

                        # Add the certificate entry to the client_certificate table
                        # certificate_entry_query = "INSERT INTO client_certificate (student_name, certificate) VALUES (%s)"
                        self.db_cursor.execute(
                            "INSERT INTO client_certificate (student_name, certificate) VALUES (%s, %s)",
                            (username, certificate), )
                        # self.db_cursor.execute(certificate_entry_query, (certificate_entry_data,))
                        self.db_connection.commit()

                        response = {"status": "success", "message": "Certificate created successfully!",
                                    "certificate": certificate}

                elif request_data["action"] == "get_grades":
                    username = self.decrypt_data(request_data["username"], shared_key)

                    self.db_cursor.execute("SELECT certificate FROM client_certificate WHERE student_name = %s",
                                           (username,))
                    existing_certificate = None
                    existing_certificate_row = self.db_cursor.fetchone()

                    if existing_certificate_row is not None:
                        query = f"SELECT * FROM grades WHERE student_name = '{username}'"
                        self.db_cursor.execute(query)

                        # استرجاع النتائج
                        results = self.db_cursor.fetchall()
                        grades_array = []
                        for row in results:
                            grade_info = {
                                'ID': row[0],
                                'Student Name': row[1],
                                'Subject': row[2],
                                'Grade': row[3],
                                'Doctor Name': row[4]
                            }
                            grades_array.append(grade_info)
                            response = {
                                "status": "success",
                                "message": "Grades retrieved successfully!",
                                "grades": grades_array
                            }

                            # يمكنك إرسال هذه الاستجابة إلى العميل
                            print(response)

                    else:
                        print("No existing certificate found for the user:", username)



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
        server = Server('0.0.0.0', 12333)
        server.start_server()
    except KeyboardInterrupt:
        server.exit_flag = True  # Set the flag when KeyboardInterrupt (Ctrl+C) is detected