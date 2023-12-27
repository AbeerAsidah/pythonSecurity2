import socket
import json
import hashlib
# import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from base64 import b64encode, b64decode
import base64
import logging



class Client:
    def __init__(self, server_address=('127.0.0.1', 12356), national_id=None):
        self.server_address = server_address
        self.shared_key = None  # سيتم تعيين المفتاح في register أو login
        self.national_id = national_id
        self.phone_number = None
        self.mobile_number = None
        self.address = None

    def pad_data(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')

        block_size = 16
        padding = block_size - (len(data) % block_size)
        return data + bytes([padding] * padding)

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
                cipher = Cipher(algorithms.AES(self.shared_key), modes.CFB(b'\x00' * 16), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(base64.b64decode(encrypted_data)) + decryptor.finalize()

                if decrypted_data is not None:
                    # print(f"Decrypted bytes (hex): {decrypted_data.hex()}")

                    decoded_data = self.remove_padding(decrypted_data)
                    if decoded_data is not None:
                        try:
                            json_response = json.loads(decoded_data.decode('utf-8'))
                            return json_response
                        except json.JSONDecodeError as json_error:
                            logging.error(f"JSON decoding error: {json_error}")
                            return None
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
            return b''  # قد تكون البيانات فارغة

        padding = data[-1]
        # print(f"Padding value: {padding}")

        if padding > len(data):
            return b''  # صورة غير صحيحة للحشو

        removed_padding_data = data[:-padding]
        # print(f"Removed padding data (hex): {removed_padding_data.hex()}")
        return removed_padding_data

    def add_additional_info(self):
        print("Please provide additional information:")
        self.phone_number = input("Phone number: ")
        self.mobile_number = input("Mobile number: ")
        self.address = input("Address: ")

        if self.shared_key is None:
            temporary_key = hashlib.sha256("temporary_key".encode()).digest()
            self.shared_key = temporary_key
            shared_key_str = base64.b64encode(self.shared_key).decode(
                'utf-8')  # Convert bytes to Base64-encoded string

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
            shared_key_str = base64.b64encode(self.shared_key).decode(
                'utf-8')  # Convert bytes to Base64-encoded string
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
     while True:
        if status == "success":
            print("1. Add Additional Information")
            print("2. Exit")

            user_choice = input("Please choose the option number: ")

            if user_choice == "1":
                # Execute the action for adding additional information
                self.get_additional_info()
            elif user_choice == "2":
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
                        request['password'] = base64.b64encode(encrypted_password).decode('utf-8') if isinstance(
                            encrypted_password, bytes) else encrypted_password

                        client.send(json.dumps(request).encode('utf-8'))

                        response = client.recv(4096)
                        # print(f"Raw server response: {response}")
                        decrypted_response = self.decrypt_data(response)
                        print(f"Decrypted server response: {decrypted_response}")

                        # server_response_data = json.loads(decrypted_response)
                        status2 = decrypted_response.get("status")
                        if status2 == "success" :
                            self.display_options(status2)


                         # Check if the server response includes the option to add additional information
                        # server_response_data = json.loads(decrypted_response)
                        # allow_additional_info = server_response_data.get("allow_additional_info", False)
                        #
                        # if allow_additional_info:
                        #     print("You can now add additional information.")
                        #     user_choice = input("Do you want to add additional information? (yes/no): ").lower()
                        #     if user_choice == "yes":
                        #         # Call the method to add additional information
                        #         self.get_additional_info()
                        #     elif user_choice == "no":
                        #         print("You chose not to add additional information.")
                        #         # Implement logic for the case where the user chooses not to add additional information
                        #     else:
                        #         print("Invalid choice. Please enter 'yes' or 'no'.")
                        #         # Implement logic to handle invalid input
                        # else:
                        #     print("Adding additional information is not allowed at the moment.")


            elif request["action"] == "add_additional_info":
                if all(key in request for key in
                       ('national_id', 'phone_number', 'mobile_number', 'address', 'shared_key')):
                    encrypted_phone_number = self.encrypt_data(request['phone_number'])
                    encrypted_mobile_number = self.encrypt_data(request['mobile_number'])
                    encrypted_address = self.encrypt_data(request['address'])
                    request2 = {
                        "action": "add_additional_info",
                        "national_id": request['national_id'],
                        "phone_number": encrypted_phone_number,
                        "mobile_number": encrypted_mobile_number,
                        "address": encrypted_address,
                        "shared_key": request['shared_key']
                    }
                    # print("Sending request:", json.dumps(request2))
                    client.send(json.dumps(request2).encode('utf-8'))

                    response2 = client.recv(4096)
                    # print(f"Raw server response: {response}")
                    decrypted_response2 = self.decrypt_data(response2)
                    print(f"Decrypted server response: {decrypted_response2}")

        except Exception as e:
            print(f"Error sending/receiving data: {e}")

        finally:
            client.close()

    def register(self, username, password, national_id):
        self.national_id = national_id  # تحديث الرقم الوطني
        self.shared_key = self.generate_key(self.national_id)  # تحديث المفتاح
        shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')  # Convert bytes to Base64-encoded string
        request = {
            "action": "register",
            "username": username,
            "password": password,
            "national_id": national_id,
            "shared_key": shared_key_str  # Include the string representation in the request
        }
        self.send_request(request)

    def login(self, username, password):
        if self.shared_key is None:
            temporary_key = hashlib.sha256("temporary_key".encode()).digest()
            self.shared_key = temporary_key
            shared_key_str = base64.b64encode(self.shared_key).decode('utf-8')  # Convert bytes to Base64-encoded string

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
            # logging.error("Failed to generate a shared key.")

# إليك كيفية استخدام العميل:
# client = Client(('127.0.0.1', 12345))  # قم بتعيين العنوان والمنفذ الخاصين بالخادم
# national_id = "123456789"  # استبدله برقم وطني حقيقي
# client.register("example_user", "example_password", national_id)
