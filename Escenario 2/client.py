import socket
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def derivar_clave(shared_key: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=24,  
        salt=None,  
        info=b'handshake data',
    )
    return hkdf.derive(shared_key)

def cifrar_mensaje(mensaje: str, clave: bytes) -> bytes:
    iv = os.urandom(16)  # AES-CBC necesita un IV de 16 bytes
    padder = padding.PKCS7(128).padder()
    datos_padded = padder.update(mensaje.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(datos_padded) + encryptor.finalize()
    return iv + cifrado  # Enviar IV + cifrado

def descifrar_mensaje(datos: bytes, clave: bytes) -> str:
    iv = datos[:16]
    cifrado = datos[16:]
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    decryptor = cipher.decryptor()
    datos_padded = decryptor.update(cifrado) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    mensaje = unpadder.update(datos_padded) + unpadder.finalize()
    return mensaje.decode()


HOST = '10.20.17.64'
PORT = 65432

# Generar clave privada y pública del cliente
client_private_key = ec.generate_private_key(ec.SECP256R1())
client_public_key = client_private_key.public_key()
client_public_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Recibir clave pública del servidor
    server_public_bytes = s.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_bytes)

    # Enviar clave pública del cliente
    s.sendall(client_public_bytes)

    # Calcular clave compartida
    shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
    clave_simetrica = derivar_clave(shared_key)
    print("Clave simetrica generada (Cliente):", clave_simetrica.hex())

    print("Conectado al servidor. Escribe 'salir' para terminar.")

    while True:
        mensaje = input("Cliente: ")
        cifrado = cifrar_mensaje(mensaje, clave_simetrica)
        s.sendall(cifrado)

        if mensaje.lower() == 'salir':
            break

        datos = s.recv(4096)
        respuesta = descifrar_mensaje(datos, clave_simetrica)
        print("Servidor:", respuesta)

        if respuesta.lower() == 'salir':
            break