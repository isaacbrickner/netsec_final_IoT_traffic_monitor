import random
from flask import Flask, render_template
from scapy.all import sniff, IP, Ether, ARP, DNS, UDP
import time
import threading
import socket  # Import socket module for reverse DNS lookup

app = Flask(__name__)

# mock devices
iot_devices = [
    {"name": "Security Camera 1", "ip": "192.168.1.10"},
    {"name": "Security Camera 2", "ip": "192.168.1.11"},
    {"name": "Thermostat", "ip": "192.168.1.12"},
    {"name": "Smart Lock", "ip": "192.168.1.13"},
    {"name": "Smart Lighting", "ip": "192.168.1.14"}
]

alerts = []

def simulate_targeting(packet):
    # randomly choose a device IP from the list to assign the actual packet dest to the mock device since the packets aren't actually going there
    device = random.choice(iot_devices)
    packet[IP].dst = device["ip"]  
    return device  

def get_domain_name(ip):
    try:
        # DNS lookup to get the domain name associated withthe IP
        domain_name = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        domain_name = "Unknown"
    return domain_name

def packet_callback(packet):
    global alerts
    # consider packets that have IP and ethernet layers
    if packet.haslayer(IP) and packet.haslayer(Ether):
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        src_mac = packet[Ether].src
        dest_mac = packet[Ether].dst
        
        if packet.haslayer(ARP):
            return 
        
        device = simulate_targeting(packet)
        
        # get the domain name from the src IP addr
        src_domain = get_domain_name(src_ip)
        
        # alert for frontend template
        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "src_mac": src_mac,
            "dest_ip": packet[IP].dst,  
            "dest_mac": dest_mac,
            "device_name": device["name"],  
            "src_domain": src_domain,  # Include the domain name
            "message": f"Suspicious packet detected from {src_ip} ({src_domain}) to {device['name']}"
        }

        alerts.append(alert)

def start_sniffing():
    sniff(prn=packet_callback, store=0)

@app.route('/')
def index():
    return render_template('index.html', alerts=alerts, iot_devices=iot_devices)

if __name__ == '__main__':
    # start sniffing packets in a separate thread so app doesn't block requests
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    app.run(debug=True, host='127.0.0.1', port=5050)
