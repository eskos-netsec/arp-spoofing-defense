import requests, json, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
# Cargar clave pública
with open("public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Solicitar tabla ARP firmada
response = requests.get("http://192.168.1.1:5000/secure_arp").json()
arp_table = response['arp_table']
signature = bytes.fromhex(response['signature'])

# Verificar firma
data = json.dumps(arp_table).encode('utf-8')
try:
    public_key.verify(
        signature,
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("✅ Firma válida. Tabla ARP confiable.")
    for ip, mac in arp_table.items():
        print(f"➕ Agregando entrada ARP: {ip} => {mac}")
        os.system(f"sudo arp -s {ip} {mac}")
except Exception as e:
    print("❌ Firma inválida. Tabla rechazada.")
