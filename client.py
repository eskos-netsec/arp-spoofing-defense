import socket
import json
from Crypto.Random import get_random_bytes

# Configuración de red
IP_PC2 = "192.168.122.211"
IP_PC1 = "192.168.122.250"
MAC_PC1 = "0C:DA:8F:2C:00:00"
PORT = 6000

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
    data = client.recv(4096).decode()
    received_data = json.loads(data)
    from Crypto.Cipher import AES
    nonce = bytes.fromhex(received_data["nonce"])
    tag = bytes.fromhex(received_data["tag"])
    ciphertext = bytes.fromhex(received_data["ciphertext"])
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    arp_table = json.loads(plaintext.decode())
    print("Tabla ARP recibida y descifrada:", arp_table)

    # Registrar tabla ARP como estática (simulado)
    print("Registrando tabla ARP como estática:", arp_table)

    # Cifrar IP y MAC de PC1 con AES
    ip_mac = {'ip': IP_PC1, 'mac': MAC_PC1}
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(json.dumps(ip_mac).encode())
    data_to_send = {
        "nonce": cipher_aes.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }
    client.sendall(json.dumps(data_to_send).encode())
