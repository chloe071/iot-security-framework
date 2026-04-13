#!/usr/bin/env python3
import sys
import traceback
sys.path.insert(0, "src")

print("Starting...", flush=True)

try:
    from discovery import DeviceDiscovery
    from service_scanner import ServiceScanner
    from risk_engine import RiskEngine
    from reporter import Reporter
    import yaml
    print("All imports OK", flush=True)
except Exception as e:
    print(f"IMPORT ERROR: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)

try:
    with open("config/config.yaml", "r") as f:
        config = yaml.safe_load(f)
    print(f"Config OK, interface: {config['network']['interface']}", flush=True)
except Exception as e:
    print(f"CONFIG ERROR: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)

try:
    discovery = DeviceDiscovery(config['network']['interface'])
    devices = discovery.discover()
    print(f"Found {len(devices)} device(s)", flush=True)
except Exception as e:
    print(f"DISCOVERY ERROR: {e}", flush=True)
    traceback.print_exc()
    sys.exit(1)

if not devices:
    print("No devices found. Are you on WiFi?", flush=True)
    sys.exit(0)

scanner = ServiceScanner()
for device in devices:
    scanner.scan_device(device)

engine = RiskEngine()
assessments = [engine.assess(d) for d in devices]

reporter = Reporter()
reporter.generate_reports(devices, assessments)