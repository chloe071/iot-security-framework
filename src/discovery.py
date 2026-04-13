import socket
import subprocess
import ipaddress
from models import Device

class DeviceDiscovery:
    def __init__(self, interface="en0"):
        self.interface = interface

    def get_local_network(self):
        try:
            result = subprocess.run(
                ["ipconfig", "getifaddr", self.interface],
                capture_output=True, text=True
            )
            ip = result.stdout.strip()
            if ip:
                print(f"  My IP: {ip}", flush=True)
                return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except Exception as e:
            print(f"  Network detect error: {e}", flush=True)
        return "192.168.1.0/24"

    def ping_scan(self, network):
        """No-root device discovery using ping"""
        devices = []
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())[:100]  # Scan first 30 hosts only
        
        print(f"  Scanning {len(hosts)} addresses...", flush=True)
        
        for ip in hosts:
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "500", str(ip)],
                    capture_output=True, timeout=2
                )
                if result.returncode == 0:
                    device = Device(ip_address=str(ip))
                    # Try hostname
                    try:
                        device.hostname = socket.gethostbyaddr(str(ip))[0]
                    except:
                        pass
                    devices.append(device)
                    print(f"  Found: {ip} ({device.hostname or 'unknown'})", flush=True)
            except:
                pass
        
        return devices

    def discover(self):
        network = self.get_local_network()
        print(f"Scanning {network} (no-root mode)...", flush=True)
        return self.ping_scan(network)