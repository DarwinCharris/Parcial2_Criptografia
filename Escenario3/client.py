import socket
from threading import Thread
import oaep

class Client:

    def __init__(self, HOST, PORT):
        self.HOST = HOST
        self.PORT = PORT
        self.client_socket = socket.socket()
        self.client_socket.connect((self.HOST, self.PORT))
        self.handle_server()

    def handle_server(self):
        Thread(target=self.recive_message).start()
        Thread(target=self.send_message).start()

    def send_message(self):
        while True:
            message = input("")
            encrypted_message = oaep.encrypt_message(message, "server-keys/public.pem")
            self.client_socket.send(encrypted_message)

    def recive_message(self):
        while True:
            encrypted_message = self.client_socket.recv(1024)
            message = oaep.decrypt_message(encrypted_message, "client-keys/private.pem")
            print(message)

Client("localhost", 8086)