import socket
import json
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

import base64
import logging
import gnupg
from CA import UniversityCertificateAuthority
from ClientCa import ClientCa

from GenerateCsr import UniversityDoctor
from clientCsr import ClientCsr


class Client:
    def __init__(self, server_address=('127.0.0.1', 12333), national_id=None):
        self.server_address = server_address
        self.shared_key = None  # سيتم تعيين المفتاح في register أو login
        self.national_id = national_id
        self.phone_number = None
        self.mobile_number = None
        self.username = None
        self.type = None
        self.address = None
        self.public_key = None
        self.private_key = None
        self.doctor = UniversityDoctor()
        self.ca = UniversityCertificateAuthority()
        self.clientCsr = ClientCsr()
        self.clientCa = ClientCa()

        # self.gpg = gnupg.GPG(gnupghome='C:\\Users\\iStore\\AppData\\Roaming\\gnupg')

    def pad_data(self, data):
        block_size = 16
        padding_size = block_size - (len(data) % block_size)
        padding = bytes([padding_size] * padding_size)
        return data + padding

    def generate_key(self, national_id):
        # Convert the national ID to a key
        try:
            shared_key = hashlib.sha256(national_id.encode()).digest()
            self.shared_key = shared_key
            return shared_key
        except Exception as e:
            logging.error(f'Shared key generation and setting error: {e}')
            return None

    def encrypt_data(self, data):
        try:
            if self.shared_key is not None:
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
                cipher = Cipher(algorithms.AES(self.shared_key), modes.CFB(b'\x00' * 16), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                return base64.b64encode(encrypted_data).decode('utf-8')
            else:
                logging.error("Shared key is None. Cannot encrypt data.")
                return None
        except Exception as e:
            logging.error(f'Encryption error: {e}')
            return None

    def decrypt_data(self, encrypted_data):
        try:

            if self.shared_key is not None:
                padding_needed = len(self.shared_key) % 4
                if padding_needed > 0:
                    # Add padding to make the length a multiple of 4
                    self.shared_key += '=' * (4 - padding_needed)

                if len(self.shared_key) not in {16, 24, 32}:
                    logging.error("Shared key length is not valid for AES.")
                    return None

                # print(f'Shared key type: {type(self.shared_key)}, length: {len(self.shared_key)}')
                cipher = Cipher(algorithms.AES(self.shared_key), modes.CFB(b'\x00' * 16), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(base64.b64decode(encrypted_data)) + decryptor.finalize()
                # print(f"Decrypted data (raw): {decrypted_data}")

                if decrypted_data is not None:
                    decoded_data = self.remove_padding(decrypted_data)
                    # print(f"Decoded data: {decoded_data}")

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

    def remove_padding(self, data):
        if not data:
            return b''  # Data may be empty

        padding = data[-1]

        if padding > len(data):
            return b''  # Incorrect padding for the data

        removed_padding_data = data[:-padding]
        return removed_padding_data

    def send_csr_to_ca0(self, name, student_sign):
        # ... (existing code)

        if self.type == "student":
            # Modify the send_request method to include the signature
            shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')
            request = {
                "action": "create_certificate",
                "student_name": name,
                "national_id": self.national_id,
                "certificate": student_sign,  # Include the signature in the request
                "shared_key": shared_key_str,

            }

            self.send_request(request)

    # def generate_pgp_key(self):
    #     try:
    #         input_data = self.gpg.gen_key_input(
    #             key_type="RSA", key_length=2048, name_email=f"{self.national_id}@example.com", passphrase="passphrase"
    #         )
    #         key = self.gpg.gen_key(input_data)
    #         return key
    #     except Exception as e:
    #         logging.error(f'PGP key generation error: {e}')
    #         return None
    #
    # def export_pgp_keys(self):
    #     try:
    #         public_key = self.gpg.export_keys(self.national_id)
    #         private_key = self.gpg.export_keys(self.national_id, True)
    #         return public_key, private_key
    #     except Exception as e:
    #         logging.error(f'Error exporting PGP keys: {e}')
    #         return None, None

    def encrypt_shared_key(self):
        try:
            gnupg_home = 'C:/Users/iStore/AppData/Roaming/gnupg'

            gpg = gnupg.GPG(gnupghome=gnupg_home)
            keys = gpg.list_keys()

            if keys:
                recipient = keys[0]['fingerprint']
                encrypted_shared_key = gpg.encrypt(self.shared_key, recipients=[recipient])
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
            # logging.debug(f'Before conversion: {encrypted_shared_key}')
            if not isinstance(encrypted_shared_key, bytes):
                encrypted_shared_key = encrypted_shared_key.encode('utf-8')

            # logging.debug(f'After conversion: {encrypted_shared_key}')
            decrypted_shared_key = gpg.decrypt(encrypted_shared_key, passphrase='qwqw1111')

            # Extract the decrypted bytes
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

    def sign_data(self, data):
        try:
            gnupg_home = 'C:/Users/iStore/AppData/Roaming/gnupg'

            gpg = gnupg.GPG(gnupghome=gnupg_home)

            # Sign the data using GPG
            signature = gpg.sign(data, keyid=self.private_key, passphrase='qwqw1111')

            if hasattr(signature, 'data') and signature.data:
                return signature.data.decode('utf-8')
            else:
                logging.error(f'Signature is not valid.')
                return None

        except Exception as e:
            logging.error(f'Signing error: {e}')
            return None

    # def input_grades(self):
    #     grades = []
    #
    #     try:
    #         num_grades = int(input("Enter the number of grades: "))
    #
    #         for _ in range(num_grades):
    #             student_name = input("Enter student name: ")
    #             subject = input("Enter subject: ")
    #             grade = int(input("Enter grade: "))
    #             grades.append({"student_name": student_name, "subject": subject, "grade": grade})
    #
    #         print("Grades successfully recorded.")
    #         return grades
    #
    #     except ValueError:
    #         print("Invalid input. Please enter valid grades.")
    #         return []

    def add_projects(self):
        projects = []
        try:
            num_projects = int(input("Enter the number of projects: "))

            for _ in range(num_projects):
                project_name = input("Enter project name: ")
                project_description = input("Enter project description: ")
                completed = input("Is the project completed? (y/n): ").lower() == 'y'
                projects.append({
                    "project_name": project_name,
                    "project_description": project_description,
                    "completed": completed,
                    "student_name": self.username
                })

            # projects_json = json.dumps(projects)  # Convert projects list to JSON
            # sign_projects = self.sign_data(projects_json)

            if self.shared_key is None:
                temporary_key = hashlib.sha256("temporary_key".encode()).digest()
                self.shared_key = temporary_key
                shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')

                request = {
                    "action": "add_projects",
                    "national_id": self.national_id,
                    "projects": projects,
                    # "sign_projects": sign_projects,
                    "shared_key": shared_key_str
                }
                self.send_request(request)

            else:
                shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')
                request = {
                    "action": "add_projects",
                    "national_id": self.national_id,
                    "projects": projects,
                    # "sign_projects": sign_projects,
                    "shared_key": shared_key_str
                }

                self.send_request(request)

        except ValueError:
            print("Invalid input. Please enter valid projects.")

    def add_grades(self):
        grades = []
        try:
            num_grades = int(input("Enter the number of grades: "))

            for _ in range(num_grades):
                student_name = input("Enter student name: ")
                subject = input("Enter subject: ")
                grade = int(input("Enter grade: "))
                doctor_name = self.username
                grades.append(
                    {"student_name": student_name, "subject": subject, "grade": grade, "doctor_name": doctor_name})

            print(f"{grades}")
            grades_json = json.dumps(grades)  # Convert list to JSON
            sign_grades = self.sign_data(grades_json)

            if self.shared_key is None:
                temporary_key = hashlib.sha256("temporary_key".encode()).digest()
                self.shared_key = temporary_key
                shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')

                request = {
                    "action": "add_grades",
                    "national_id": self.national_id,
                    "grades": grades,
                    "sign_grades": sign_grades,
                    "shared_key": shared_key_str
                }
                self.send_request(request)



            else:
                shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')
                request = {
                    "action": "add_grades",
                    "national_id": self.national_id,
                    "grades": grades,
                    "sign_grades": sign_grades,
                    "shared_key": shared_key_str
                }

                self.send_request(request)
        except ValueError:
            print("Invalid input. Please enter valid grades.")

    def get_grades_for1user(self):

        if self.shared_key is None:
            temporary_key = hashlib.sha256("temporary_key".encode()).digest()
            self.shared_key = temporary_key
            shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')

            request = {
                "action": "get_grades",
                "username": self.username,
                "shared_key": shared_key_str
            }
            self.send_request(request)
        else:
            shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')
            request = {
                "action": "get_grades",
                "username": self.username,
                "shared_key": shared_key_str
            }

            self.send_request(request)

    def add_additional_info(self):
        print("Please provide additional information:")
        self.phone_number = input("Phone number: ")
        self.mobile_number = input("Mobile number: ")
        self.address = input("Address: ")

        if self.shared_key is None:
            temporary_key = hashlib.sha256("temporary_key".encode()).digest()
            self.shared_key = temporary_key
            shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')

            request = {
                "action": "add_additional_info",
                "national_id": self.national_id,
                "phone_number": self.phone_number,
                "mobile_number": self.mobile_number,
                "address": self.address,
                "shared_key": shared_key_str
            }
            self.send_request(request)
        else:
            shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')
            request = {
                "action": "add_additional_info",
                "national_id": self.national_id,
                "phone_number": self.phone_number,
                "mobile_number": self.mobile_number,
                "address": self.address,
                "shared_key": shared_key_str
            }

            self.send_request(request)

    def get_additional_info(self):
        # Check if there are existing additional information
        if self.phone_number or self.mobile_number or self.address:
            print("Existing additional information found:")
            print(f"Phone number: {self.phone_number}")
            print(f"Mobile number: {self.mobile_number}")
            print(f"Address: {self.address}")

            update_choice = input("Do you want to update the existing additional information? (yes/no): ").lower()
            if update_choice == "yes":
                # Allow the user to update the existing information
                self.add_additional_info()
            else:
                print("You chose not to update the existing additional information.")
                # Implement logic for the case where the user chooses not to update
        else:
            # No existing additional information found, proceed with adding new information
            self.add_additional_info()

    def display_options(self, status):
        # print(message)

        if (self.type == "student"):
            while True:
                if status == "success":
                    print("1. Add Additional Information")
                    # print("2. Add list of grades ")
                    print("2. Add list of projects ")
                    # print("4. Create Signed Certificate")
                    print("3. Get grades of student ")
                    print("4. Exit")

                    user_choice = input("Please choose the option number: ")

                    if user_choice == "1":
                        # Execute the action for adding additional information
                        self.get_additional_info()

                    elif user_choice == "2":
                        self.add_projects()
                    elif user_choice == "3":
                        self.get_grades_for1user()
                    elif user_choice == "4":
                        print("Exiting the program.")
                        break
                    else:
                        print("Invalid choice.")
                else:
                    print("No additional options available.")
        else:
            while True:
                if status == "success":
                    print("1. Add Additional Information")
                    print("2. Add list of grades ")
                    print("3. Exit")

                    user_choice = input("Please choose the option number: ")

                    if user_choice == "1":
                        # Execute the action for adding additional information
                        self.get_additional_info()

                    elif user_choice == "2":
                        self.add_grades()

                    elif user_choice == "3":
                        print("Exiting the program.")
                        break
                    else:
                        print("Invalid choice.")
                else:
                    print("No additional options available.")

    def send_request(self, request):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(self.server_address)

        try:
            if request["action"] == "login" or request["action"] == "register":
                if 'password' in request:
                    if len(request['password']) < 8:
                        response = {"status": "failure", "message": "Invalid input length."}
                        print(response)  # Handle the response appropriately
                    else:
                        hashed_password = hashlib.sha256(request['password'].encode('utf-8')).hexdigest()
                        encrypted_password = self.encrypt_data(hashed_password)
                        encrypted_password2 = base64.b64encode(encrypted_password).decode('utf-8') if isinstance(
                            encrypted_password, bytes) else encrypted_password
                        self.username = request['username']
                        encrypted_user_name = self.encrypt_data(request['username'])
                        encrypted_shared_key = self.encrypt_shared_key()
                        action = request['action']
                        if 'national_id' in request and 'type' in request:
                            encrypted_national_id = self.encrypt_data(request['national_id'])
                            user_type = request.get('type', '')
                            print(f"here")
                            if user_type not in ('student', 'doctor'):
                                print("Error: Type must be either 'student' or 'doctor'")
                            else:
                                encrypted_type = self.encrypt_data(user_type)

                                requestt = {
                                    "action": action,
                                    "username": encrypted_user_name,
                                    "password": encrypted_password2,
                                    "national_id": encrypted_national_id,
                                    "type": encrypted_type,
                                    "shared_key": encrypted_shared_key
                                }
                                client.send(json.dumps(requestt).encode('utf-8'))

                        else:
                            requestt = {
                                "action": action,
                                "username": encrypted_user_name,
                                "password": encrypted_password2,
                                # "national_id": encrypted_national_id,
                                "shared_key": encrypted_shared_key
                            }
                            client.send(json.dumps(requestt).encode('utf-8'))

                        response = client.recv(4096)
                        # print(f"Raw server response: {response}")
                        decrypted_response = self.decrypt_data(response)
                        print(f"Decrypted server response: {decrypted_response}")
                        response_dict = json.loads(decrypted_response)


                        # Parse the JSON string into a dictionary
                        if request["action"] == "login":

                            self.type = response_dict.get("type")
                            print("type: ", self.type)

                        # Now you can use .get() on the dictionary

                        status2 = response_dict.get("status")
                        if status2 == "success":
                            if request["action"] == "register":
                                print("Create signed certificate")
                                if (self.type == "student"):
                                    csr, student_sign = self.clientCsr.send_csr_to_ca1(self.clientCa, self.username,
                                                                                       self.national_id)
                                    signature = self.clientCsr.verify_certificate1(student_sign,
                                                                                   self.clientCa.cca_private_key.public_key(),
                                                                                   csr)
                                    self.send_csr_to_ca0(self.username, signature)
                                else:
                                    csr, doctor_sign = self.doctor.send_csr_to_ca(self.ca, self.username,
                                                                                  self.national_id)
                                    self.doctor.verify_certificate(doctor_sign, self.ca.ca_private_key.public_key(),
                                                                   csr)
                            self.display_options(status2)


            elif request["action"] == "add_additional_info":
                if all(key in request for key in
                       ('national_id', 'phone_number', 'mobile_number', 'address', 'shared_key')):
                    encrypted_phone_number = self.encrypt_data(request['phone_number'])
                    encrypted_mobile_number = self.encrypt_data(request['mobile_number'])
                    encrypted_address = self.encrypt_data(request['address'])
                    encrypted_shared_key = self.encrypt_shared_key()
                    request2 = {
                        "action": "add_additional_info",
                        "national_id": request['national_id'],
                        "phone_number": encrypted_phone_number,
                        "mobile_number": encrypted_mobile_number,
                        "address": encrypted_address,
                        "shared_key": encrypted_shared_key
                    }
                    # print("Sending request:", json.dumps(request2))
                    client.send(json.dumps(request2).encode('utf-8'))

                    response2 = client.recv(4096)
                    # print(f"Raw server response: {response}")
                    decrypted_response2 = self.decrypt_data(response2)
                    print(f"Decrypted server response: {decrypted_response2}")

            elif request["action"] == "add_grades":
                if all(key in request for key in
                       ('national_id', 'grades', 'sign_grades', 'shared_key')):
                    grades = request.get("grades", "")
                    print(f"grades :{grades}")
                    grades_json = json.dumps(grades)

                    encrypted_grades = self.encrypt_data(grades_json)
                    print(f"enc_grades :{encrypted_grades}")

                    print(f"sign_grades :{request.get("sign_grades", "")}")

                    encrypted_sign_grades = self.encrypt_data(request.get("sign_grades", ""))
                    print(f"sign_grades :{encrypted_sign_grades}")

                    encrypted_shared_key = self.encrypt_shared_key()
                    request2 = {
                        "action": "add_grades",
                        "national_id": request['national_id'],
                        "grades": encrypted_grades,
                        "sign_grades": encrypted_sign_grades,
                        "shared_key": encrypted_shared_key
                    }
                    # print("Sending request:", json.dumps(request2))
                    client.send(json.dumps(request2).encode('utf-8'))

                    response2 = client.recv(4096)
                    # print(f"Raw server response: {response}")
                    decrypted_response2 = self.decrypt_data(response2)
                    print(f"Decrypted server response: {decrypted_response2}")



            elif request["action"] == "add_projects":
                if all(key in request for key in
                       ('national_id', 'projects', 'shared_key')):
                    projects = request.get("projects", "")
                    print(f"projects :{projects}")
                    projects_json = json.dumps(projects)

                    encrypted_projects = self.encrypt_data(projects_json)
                    print(f"enc_projects :{encrypted_projects}")

                    # print(f"sign_projects :{request.get("sign_projects", "")}")
                    # encrypted_sign_projects = self.encrypt_data(request.get("sign_projects", ""))
                    # print(f"sign_projects :{encrypted_sign_projects}")

                    encrypted_shared_key = self.encrypt_shared_key()
                    request2 = {
                        "action": "add_projects",
                        "national_id": request['national_id'],
                        "projects": encrypted_projects,
                        # "sign_projects": encrypted_sign_projects,
                        "shared_key": encrypted_shared_key
                    }

                    client.send(json.dumps(request2).encode('utf-8'))
                    response2 = client.recv(4096)
                    decrypted_response2 = self.decrypt_data(response2)
                    print(f"Decrypted server response: {decrypted_response2}")


            elif request["action"] == "create_certificate":
                encrypted_name = request.get('student_name')
                gg = request.get('certificate')
                gg_base64 = base64.b64encode(gg).decode('utf-8')
                encrypted_shared_key = self.encrypt_shared_key()

                request3 = {
                    "action": "create_certificate",
                    "student_name": encrypted_name,
                    "certificate": gg_base64,
                    "shared_key": encrypted_shared_key
                }
                client.send(json.dumps(request3).encode('utf-8'))

                response3 = client.recv(4096)
                decrypted_response3 = self.decrypt_data(response3)
                print(f"Decrypted server response: {decrypted_response3}")

            elif request["action"] == "get_grades":
                if all(key in request for key in
                       ('username', 'shared_key')):
                    encrypted_username = self.encrypt_data(request['username'])
                    encrypted_shared_key = self.encrypt_shared_key()
                    request2 = {
                        "action": "get_grades",
                        "username": encrypted_username,
                        "shared_key": encrypted_shared_key
                    }
                    client.send(json.dumps(request2).encode('utf-8'))

                    response2 = client.recv(4096)
                    decrypted_response2 = self.decrypt_data(response2)
                    print(f"Decrypted server response: {decrypted_response2}")


        except Exception as e:
            print(f"Error sending/receiving data: {e}")

        finally:
            client.close()

    def register(self, username, type1, password, national_id):
        self.type = type1
        self.national_id = national_id
        self.shared_key = self.generate_key(self.national_id)
        # Convert bytes to Base64-encoded string
        shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')
        request = {
            "action": "register",
            "username": username,
            "type": type1,
            "password": password,
            "national_id": national_id,
            "shared_key": shared_key_str
        }
        self.send_request(request)

    def login(self, username, password):
        if self.shared_key is None:
            temporary_key = hashlib.sha256("temporary_key".encode()).digest()
            self.shared_key = temporary_key
            # Convert bytes to Base64-encoded string
            shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')

            request = {
                "action": "login",
                "username": username,
                "password": password,
                # "national_id": self.national_id,
                "shared_key": shared_key_str
            }
            self.send_request(request)
        else:
            shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')  # Convert bytes to Base64-encoded string
            request = {
                "action": "login",
                "username": username,
                "password": password,
                # "national_id": self.national_id,
                "shared_key": shared_key_str
            }
            self.send_request(request)
