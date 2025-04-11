import socket
from threading import Thread
import oaep
import time

class Server:
    def __init__(self, HOST, PORT):
        self.HOST = HOST
        self.PORT = PORT
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.HOST, self.PORT))
        self.server_socket.listen()
        print(f"Server started on {self.HOST}:{self.PORT}")
        print("Waiting for connections...")
        self.client_socket, client_address = self.server_socket.accept()
        print(f"Connection from {client_address} has been established.")

        self.handle_client()

    def handle_client(self):
        Thread(target=self.recive_message).start()
        Thread(target=self.send_message).start()
    

    def send_message(self):
        while True:
            message = input("")
            start_time = time.time()
            encrypted_message = oaep.encrypt_message(message, "client-keys/public.pem")
            message_length = len(encrypted_message)
            end_time = time.time()
            total_time = end_time - start_time
            print(f"Encryption time: {total_time:.6f} seconds")
            print(f"Sending message of length {message_length} bytes")
            self.client_socket.send(encrypted_message)

    def recive_message(self):
        while True:
            encrypted_message = self.client_socket.recv(1024)
            message_length = len(encrypted_message)
            start_time = time.time()
            message = oaep.decrypt_message(encrypted_message, "server-keys/private.pem")
            end_time = time.time()
            total_time = end_time - start_time
            print(f"Decryption time: {total_time:.6f} seconds")
            print(f"Received message of length {message_length} bytes")
            print(message)

Server("localhost", 5432)