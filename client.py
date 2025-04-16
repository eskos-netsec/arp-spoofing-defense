import socket
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Configuración de red
IP_PC2 = "192.168.10.2"
IP_PC1 = "192.168.10.1"
MAC_PC1 = "00:00:00:00:00:01"
PORT = 5000

# Conectar a PC2
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((IP_PC2, PORT))
    print("Conectado a PC2")

    # Recibir clave pública RSA
    public_key = json.loads(client.recv(1024).decode())
    print("Clave pública RSA recibida:", public_key)

    # Generar clave AES
    aes_key = get_random_bytes(16)
    print("Clave AES generada:", aes_key)

    # Cifrar clave AES con RSA
    encrypted_aes_key = pow(int.from_bytes(aes_key, 'big'), public_key[0], public_key[1]).to_bytes((public_key[1].bit_length() + 7) // 8, 'big')
    client.sendall(encrypted_aes_key)

    # Recibir tabla ARP cifrada
    data = client.recv(1024)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    arp_table = json.loads(cipher_aes.decrypt_and_verify(ciphertext, tag).decode())
    print("Tabla ARP recibida y descifrada:", arp_table)

    # Registrar tabla ARP como estática (simulado)
    print("Registrando tabla ARP como estática:", arp_table)

    # Cifrar IP y MAC de PC1 con AES
    ip_mac = {'ip': IP_PC1, 'mac': MAC_PC1}
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(json.dumps(ip_mac).encode())
    client.sendall(cipher_aes.nonce + tag + ciphertext)
