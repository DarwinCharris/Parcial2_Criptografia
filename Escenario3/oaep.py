from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

def encrypt_message(message, public_key_path):
    # Load the public key
    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())

    # Create a cipher object using OAEP padding
    cipher = PKCS1_OAEP.new(public_key)

    # Encrypt the message
    encrypted_message = cipher.encrypt(message.encode())

    return encrypted_message

def decrypt_message(encrypted_message, private_key_path):
    # Load the private key
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    # Create a cipher object using OAEP padding
    cipher = PKCS1_OAEP.new(private_key)

    # Decrypt the message
    decrypted_message = cipher.decrypt(encrypted_message)

    return decrypted_message.decode()