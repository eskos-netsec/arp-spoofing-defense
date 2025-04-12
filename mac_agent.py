# mac_agent.py
from flask import Flask, jsonify
import json

app = Flask(__name__)

# Tabla ARP confiable (puede cargarse dinámicamente o desde una BD)
arp_table = {
    "192.168.1.10": "00:11:22:33:44:55",
    "192.168.1.11": "00:11:22:33:44:66",
    "192.168.1.12": "00:11:22:33:44:77"
}

@app.route('/arp')
def get_arp_table():
    return jsonify(arp_table)

@app.route('/arp/<ip>')
def get_mac(ip):
    mac = arp_table.get(ip)
    if mac:
        return jsonify({ip: mac})
    return jsonify({"error": "IP not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
