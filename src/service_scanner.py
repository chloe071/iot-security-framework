import socket
import requests
from models import Device

COMMON_PORTS = [22, 80, 443, 1883, 5683, 8080, 554, 5000, 1900]

class ServiceScanner:
    def scan_device(self, device):
        print(f"   📡 Scanning {device.ip_address}...")
        for port in COMMON_PORTS:
            sock = socket.socket()
            sock.settimeout(2)
            if sock.connect_ex((device.ip_address, port)) == 0:
                device.open_ports.append(port)
                
                if port == 80:
                    device.protocols.append("HTTP")
                elif port == 443:
                    device.protocols.append("HTTPS")
                elif port == 22:
                    device.protocols.append("SSH")
                elif port == 1883:
                    device.protocols.append("MQTT")
        
        device.services = {f"port_{p}": "open" for p in device.open_ports}
        return device