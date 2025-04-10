import json
import time
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import ChaCha20

# Valores interceptados
u = 17598168892733130391566217744845998889694531931551147285608237381072472660434133293445090495506595018774813914903309777980200861765453361704173814647635791525292316903772755710128675464670626885504528080504079333317887538279587351516496648895530035354170189785437788553439810330339148821596626498404904650378
v = 127036701545378485708465909967118344803342101921702605595401352962527749802413890744330777519770913351842559558288784132663436011172481138217263462611136331089867995614957006444846552775494124336415987606961648391399530980193079721791331677306333606829185203894497645474195117126417341193403626000342563044550
hex_data = "f5b98c8b67557a06072379013bf6d07628f9e86b718f6453b97c0b52bb93efba824f81f4ccd9d5b03314fb9906b67e0080c9ec1dea33c713496fae5976"
data = bytes.fromhex(hex_data)
nonce = data[:8]
ciphertext = data[8:]

escenario = int(input("Elige el escenario (1-5): "))
if escenario not in [1, 2, 3, 4, 5]:
    print("Escenario no válido.")
    exit()

# Cargar parámetros del escenario seleccionado
with open("Escenario1/parameters.json", "r") as file:
    parameters = json.load(file)["parameters"][escenario - 1]

p = parameters["p"]
q = parameters["q"]
g = parameters["g"]

print(f"Parámetros del escenario {escenario}: p={p}, q={q}, g={g}")

# Medir tiempo de búsqueda de beta
start = time.time()
timeout = 3600  # 1 hora en segundos

found = False
for beta in range(0, q):
    if time.time() - start > timeout:
        print("[-] Tiempo excedido: no se pudo encontrar beta en menos de una hora.")
        exit()
    if pow(g, beta, p) == v:
        found = True
        end = time.time()
        print(f"[+] Se encontró beta: {beta}")
        print(f"[⏱] Tiempo en encontrar beta: {end - start:.6f} segundos")
        break

if not found:
    print("[-] No se encontró beta.")
    exit()

# Calcular clave compartida
w = pow(u, beta, p)
key = HKDF(master=w.to_bytes(32, 'big'), key_len=32, salt=b'', hashmod=SHA256)

# Intentar descifrar el mensaje
try:
    start = time.time()
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext).decode()
    end = time.time()
    print(f"[+] Mensaje descifrado: {plaintext}")
    print(f"[⏱] Tiempo en descifrar mensaje: {end - start:.6f} segundos")
except Exception as e:
    print("[-] No se pudo descifrar el mensaje:", e)
