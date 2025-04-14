import socket
import json
import netifaces
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

# Configuración
HOST = '192.168.1.1'
PORT = 5000
INTERFACE = 'eth0'  # Cambia según tu interfaz en GNS3

# Generar claves RSA
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()
cipher_rsa = PKCS1_OAEP.new(private_key)

# Tabla ARP confiable inicial (puedes llenarla manualmente o con arp-scan)
arp_table = {
    '192.168.1.1': '00:14:22:01:23:45',  # Ejemplo, ajusta según tu red
}

def get_local_mac(interface):
    return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']

def send_data(client_socket, data):
    client_socket.send(json.dumps(data).encode())

def receive_data(client_socket):
    return json.loads(client_socket.recv(1024).decode())

# Servidor
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen()
    print(f"MAC Agent escuchando en {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        with client_socket:
            print(f"Conexión desde {addr}")

            # Enviar clave pública RSA
            send_data(client_socket, {'public_key': base64.b64encode(public_key.export_key()).decode()})

            # Recibir clave AES cifrada
            data = receive_data(client_socket)
            encrypted_aes_key = base64.b64decode(data['aes_key'])
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)

            # Cifrar tabla ARP con AES
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(json.dumps(arp_table).encode())
            send_data(client_socket, {
                'nonce': base64.b64encode(cipher_aes.nonce).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'tag': base64.b64encode(tag).decode()
            })

            # Recibir IP y MAC del cliente
            data = receive_data(client_socket)
            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=base64.b64decode(data['nonce']))
            client_data = json.loads(cipher_aes.decrypt_and_verify(
                base64.b64decode(data['ciphertext']),
                base64.b64decode(data['tag'])
            ).decode())
            
            # Actualizar tabla ARP
            arp_table[client_data['ip']] = client_data['mac']
            print(f"Tabla ARP actualizada: {arp_table}")
