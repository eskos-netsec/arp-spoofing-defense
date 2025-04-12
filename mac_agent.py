from flask import Flask, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import json

app = Flask(__name__)

# Tabla ARP confiable
arp_table = {
    "192.168.1.10": "00:11:22:33:44:10",
    "192.168.1.20": "00:11:22:33:44:20"
}

with open("private.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

def sign_data(data):
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

@app.route('/secure_arp')
def get_signed_arp():
    arp_json = json.dumps(arp_table).encode('utf-8')
    signature = sign_data(arp_json)
    return jsonify({
        "arp_table": arp_table,
        "signature": signature.hex()
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

