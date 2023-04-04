import hashlib
import os

def encrypt_simple_message(message):
    # Hash message using SHA256
    hashed_message = hashlib.sha256(message.encode("utf-8")).hexdigest()
    # Return print
    return f"Hashed Message: {hashed_message}"

def encrypt_salt_message(message):
    # Generate random salt bytes
    salt = os.urandom(32)
    # Add salt to message
    salted_message = salt + message.encode("utf-8")
    # Hash salted message using SHA256
    hashed_message = hashlib.sha256(salted_message).hexdigest()
    # Reutrn results
    return f"Salt: {salt.hex()}\nHashed message with salt: {hashed_message}"

def check_simple_message(input_message, input_encrypted_message):
    # Hash input message using SHA256
    hashed_input = hashlib.sha256(input_message.encode("utf-8")).hexdigest()
    # Check if hashed input matches original hash and return print
    if hashed_input == input_encrypted_message:
        return f"Input matches original message!"
    else:
        return f"Input does not match original message!"

def check_salt_message(input_message, input_salt, input_encrypted_message):
    # Convert salt hex to bytes
    bytes_salt = bytes.fromhex(input_salt)
    # Hash salted input using SHA256 and the original salt
    salted_input = bytes_salt + input_message.encode("utf-8")
    # Hash input message using SHA256
    hashed_input = hashlib.sha256(salted_input).hexdigest()
    # Check if hashed input matches original hash and return print
    if hashed_input == input_encrypted_message:
        return f"Input matches original message!"
    else:
        return f"Input does not match original message!"

def main_menu():
    while True:
        # Menu prints
        print("---- Encrypt your text ----")
        print("* Please be aware that the script generates a different salt every time you encrypt a message")
        print("* Save salt and hash if you want to validate later")
        print("-- Menu --")
        print("1. Encrypt a SHA256 salted message")
        print("2. Check your SHA256 salted message")
        print("3. Exit")
        # User choice
        choice = input("Enter your choice (1-3): ")
        # Menu navigation
        if choice == "1":
            encrypt_menu()
        elif choice == "2":
            decrypt_menu()
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 3.")

def encrypt_menu():
    while True:
        # Menu prints        
        print("---- Encrypt a SHA256 salted message ----")
        print("-- Menu --")
        print("* Please be aware that the script generates a different salt every time you encrypt a message")
        print("* Save salt and hash if you want to validate later")        
        print("1. Encrypt your message - with salt")
        print("2. Encrypt your message - no salt")
        print("3. Back")
        # User choice
        choice = input("Enter your choice (1-3): ")
        # Menu navigation
        if choice == "1":
            message = input("Enter your message: ")
            print("!!! Save salt and hash if you want to validate later !!! ")
            print(encrypt_salt_message(message))
            print("--------")
        elif choice == "2":
            message = input("Enter your message: ")
            print("!!! Save hash if you want to validate later !!! ")
            print(encrypt_simple_message(message))
            print("--------")
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 3.")

def decrypt_menu():
    while True:
        # Menu prints
        print("---- Check your SHA256 salted message ----")
        print("- Menu -")
        print("1. Check your message - with salt")
        print("2. Check your message - no salt")
        print("3. Go back")
        # User choice
        choice = input("Enter your choice (1-3): ")
        # Menu navigation
        if choice == "1":
            message = input("Enter your message: ")
            original_salt = input("Enter original salt: ")
            original_message_hash = input("Enter original message hash: ")
            print(check_salt_message(message, original_salt, original_message_hash))
            print("--------")
        elif choice == "2":
            message = input("Enter your message: ")
            original_message_hash = input("Enter original message hash: ")
            print(check_simple_message(message, original_message_hash))
            print("--------")
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 3.")

# Main loop
if __name__ == "__main__":
    main_menu()







