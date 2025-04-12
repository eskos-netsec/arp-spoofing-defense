#!/bin/bash

# Dirección IP del MAC-Agent
MAC_AGENT_IP="192.168.1.1"

# Consultar la tabla ARP desde la API
curl -s http://$MAC_AGENT_IP:5000/arp | jq -r 'to_entries[] | "\(.key) \(.value)"' | while read ip mac; do
    echo "Estableciendo ARP estático para $ip => $mac"
    sudo arp -s $ip $mac
done
