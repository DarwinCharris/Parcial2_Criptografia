import socket
import threading
import json
import random
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import ChaCha20
from Cryptodome.Random import get_random_bytes

def receive_messages(sock, key):
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break
            nonce = data[:8]
            ciphertext = data[8:]
            cipher = ChaCha20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext).decode()
            print(f"Alice: {plaintext}")
        except Exception as e:
            print("Error recibiendo mensaje:", e)
            break

def send_messages(sock, key):
    while True:
        message = input()
        if message.lower() == 'salir':
            break
        nonce = get_random_bytes(8)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(message.encode())
        sock.sendall(nonce + ciphertext)

def load_parameters():
    with open("Escenario1/parameters.json", "r") as file:
        return json.load(file)["parameters"]

def generate_beta(q):
    return random.randint(0, q - 2)

HOST = '127.0.0.1'
PORT = 65432

def init_connection():
    parameters = load_parameters()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print("Esperando conexión...")
        conn, _ = s.accept()
        print("Conexión con Alice establecida.")

        scenario, u = conn.recv(1024).decode().split("|")
        u = int(u)
        num = int(scenario) - 1
        p, q, g = parameters[num]["p"], parameters[num]["q"], parameters[num]["g"]

        beta = generate_beta(q)
        v = pow(g, beta, p)
        print(f'Valor v= {v}')
        conn.sendall(str(v).encode())

        w = pow(u, beta, p)
        w_bytes = w.to_bytes((w.bit_length() + 7) // 8, byteorder='big')
        key = HKDF(master=w_bytes, key_len=32, salt=b'', hashmod=SHA256)

        threading.Thread(target=receive_messages, args=(conn, key), daemon=True).start()
        send_messages(conn, key)

if __name__ == "__main__":
    init_connection()
