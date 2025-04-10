import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def cifrar_mensaje(mensaje: str, clave: bytes) -> bytes:
    iv = os.urandom(16)  # IV aleatorio de 16 bytes para AES-CBC
    padder = padding.PKCS7(128).padder()
    datos_padded = padder.update(mensaje.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(datos_padded) + encryptor.finalize()
    return iv + cifrado  # Concatenamos IV + mensaje cifrado

def descifrar_mensaje(datos: bytes, clave: bytes) -> str:
    iv = datos[:16]
    cifrado = datos[16:]
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    decryptor = cipher.decryptor()
    datos_padded = decryptor.update(cifrado) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    mensaje = unpadder.update(datos_padded) + unpadder.finalize()
    return mensaje.decode()

def derivar_clave(shared_key: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=24, 
        salt=None,  
        info=b'handshake data',
    )
    return hkdf.derive(shared_key)


HOST = '10.20.17.64'
PORT = 65433

# Generar clave privada y pública del servidor
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()
server_public_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("Esperando conexión del cliente...")

    conn, addr = s.accept()
    with conn:
        print(f"Conectado por {addr}")

        # Enviar clave pública al cliente
        conn.sendall(server_public_bytes)

        # Recibir clave pública del cliente
        client_public_bytes = conn.recv(1024)
        client_public_key = serialization.load_pem_public_key(client_public_bytes)

        # Calcular clave compartida
        shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
        clave_simetrica = derivar_clave(shared_key)
        print("Clave simétrica generada (Servidor):", clave_simetrica.hex())

        while True:
            datos = conn.recv(4096)
            mensaje = descifrar_mensaje(datos, clave_simetrica)
            print("Cliente:", mensaje)

            if mensaje.lower() == 'salir':
                break

            respuesta = input("Servidor: ")
            cifrado = cifrar_mensaje(respuesta, clave_simetrica)
            conn.sendall(cifrado)

            if respuesta.lower() == 'salir':
                break

