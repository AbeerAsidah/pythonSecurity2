# from server import start_server
# from client import register, login
from client import Client
import threading
import time

def main():
    # Run the server in a separate thread
    # server_thread = threading.Thread(target=start_server)
    # server_thread.start()

    # Simulate a delay before running the client (adjust as needed)
    # time.sleep(2)

    client = Client()

    while True:
        print("Choose an option:")
        print("1. Register a new account")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == "1":
            # Register a new user
            register_username = input("Enter username for registration: ")
            type1 = input(" Enter your type ( student/doctor) ")
            national_id = input("Enter national ID for registration: ")
            register_password = input("Enter password for registration: ")
            client.register(register_username, type1, register_password, national_id)
            # client.get_additional_info()

        elif choice == "2":
            # Login with an existing user
            login_username = input("Enter username for login: ")
            login_password = input("Enter password for login: ")
            client.login(login_username, login_password)

        elif choice == "3":
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()