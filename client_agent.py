import socket
import json
import netifaces
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

# Configuración
MAC_AGENT_HOST = '192.168.1.1'
PORT = 5000
INTERFACE = 'eth0'  # Cambia según tu interfaz en GNS3

def get_local_ip(interface):
    return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']

def get_local_mac(interface):
    return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']

def send_data(sock, data):
    sock.send(json.dumps(data).encode())

def receive_data(sock):
    return json.loads(sock.recv(1024).decode())

# Conectar al MAC Agent
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((MAC_AGENT_HOST, PORT))

    # Recibir clave pública RSA
    data = receive_data(sock)
    public_key = RSA.import_key(base64.b64decode(data['public_key']))
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # Generar y enviar clave AES
    aes_key = get_random_bytes(16)  # Clave AES de 128 bits
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    send_data(sock, {'aes_key': base64.b64encode(encrypted_aes_key).decode()})

    # Recibir tabla ARP cifrada
    data = receive_data(sock)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=base64.b64decode(data['nonce']))
    arp_table = json.loads(cipher_aes.decrypt_and_verify(
        base64.b64decode(data['ciphertext']),
        base64.b64decode(data['tag'])
    ).decode())
    print(f"Tabla ARP recibida: {arp_table}")

    # Registrar tabla ARP estática
    for ip, mac in arp_table.items():
        os.system(f"sudo arp -s {ip} {mac}")

    # Enviar IP y MAC propias cifradas
    client_data = {'ip': get_local_ip(INTERFACE), 'mac': get_local_mac(INTERFACE)}
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(json.dumps(client_data).encode())
    send_data(sock, {
        'nonce': base64.b64encode(cipher_aes.nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode()
    })
