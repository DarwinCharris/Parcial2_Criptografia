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
            print(f"Bob: {plaintext}")
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
        print(f"Mensaje cifrado: {(nonce + ciphertext).hex()}")
        sock.sendall(nonce + ciphertext)

def load_parameters():
    with open("Escenario1/parameters.json", "r") as file:
        return json.load(file)["parameters"]

def generate_alpha(q):
    return random.randint(0, q - 2)

HOST = '127.0.0.1'
PORT = 65432

def init_connection():
    scenario = input("Elige el escenario (1-5): ")
    while scenario not in ['1', '2', '3', '4', '5']:
        print("Escenario no válido. Por favor, elige un número entre 1 y 5.")
        scenario = input("Elige el escenario (1-5): ")

    parameters = load_parameters()
    num = int(scenario) - 1
    p, q, g = parameters[num]["p"], parameters[num]["q"], parameters[num]["g"]
    
    alpha = generate_alpha(q)
    u = pow(g, alpha, p)
    print(f'Valor u= {u}')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Conexión con Bob establecida.")
        s.sendall(f"{scenario}|{u}".encode())

        v = int(s.recv(1024).decode())
        w = pow(v, alpha, p)
        w_bytes = w.to_bytes((w.bit_length() + 7) // 8, byteorder='big')
        key = HKDF(master=w_bytes, key_len=32, salt=b'', hashmod=SHA256)

        threading.Thread(target=receive_messages, args=(s, key), daemon=True).start()
        send_messages(s, key)

if __name__ == "__main__":
    init_connection()
