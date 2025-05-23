import socket
import json
from scapy.all import ARP, Ether, srp
from Crypto.Random import get_random_bytes

# Función para escanear ARP y obtener la tabla ARP
def arp_scan(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    arp_table = {}
    for sent, received in result:
        arp_table[received.psrc] = received.hwsrc
    return arp_table

# Función para cifrar con RSA (simplificado con primos pequeños)
def rsa_encrypt(message, pub_key):
    e, n = pub_key
    cipher = pow(int.from_bytes(message, 'big'), e, n)
    return cipher.to_bytes((n.bit_length() + 7) // 8, 'big')

# Función para descifrar con RSA
def rsa_decrypt(ciphertext, priv_key):
    d, n = priv_key
    message = pow(int.from_bytes(ciphertext, 'big'), d, n)
    return message.to_bytes((n.bit_length() + 7) // 8, 'big')

# Configuración de red
IP_PC2 = "192.168.122.211"
PORT = 6000

# Escanear ARP para obtener la tabla confiable
arp_table = arp_scan("192.168.122.0/24")
print("Tabla ARP confiable de PC2:", arp_table)

# Generar claves RSA con primos pequeños
p = 61
q = 53
n = p * q
phi = (p - 1) * (q - 1)
e = 17  # Coprimo con phi
d = pow(e, -1, phi)  # Inverso modular
public_key = (e, n)
private_key = (d, n)

# Iniciar servidor TCP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((IP_PC2, PORT))
    server.listen()
    print("PC2 esperando conexión...")
    conn, addr = server.accept()
    with conn:
        print("Conectado a", addr)

        # Enviar clave pública RSA a PC1
        conn.sendall(json.dumps(public_key).encode())

        # Recibir clave AES cifrada de PC1
        encrypted_aes_key = conn.recv(1024)
        aes_key = rsa_decrypt(encrypted_aes_key, private_key)
        print("Clave AES recibida:", aes_key)

        # Cifrar tabla ARP con AES
        from Crypto.Cipher import AES
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(json.dumps(arp_table).encode())

        # Enviar datos en formato JSON
        data_to_send = {
            "nonce": cipher_aes.nonce.hex(),
            "tag": tag.hex(),
            "ciphertext": ciphertext.hex()
        }
        conn.sendall(json.dumps(data_to_send).encode())

        # Recibir IP y MAC cifradas de PC1
        data = conn.recv(4096).decode()
        received_data = json.loads(data)
        nonce = bytes.fromhex(received_data["nonce"])
        tag = bytes.fromhex(received_data["tag"])
        ciphertext = bytes.fromhex(received_data["ciphertext"])
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        ip_mac = json.loads(decrypted_data.decode())
        print("IP y MAC de PC1:", ip_mac)

        # Agregar a la tabla ARP (simulado)
        arp_table[ip_mac['ip']] = ip_mac['mac']
        print("Tabla ARP actualizada:", arp_table)
