# IoT Security Assessment Framework

A Python tool that discovers devices on a local network, checks common IoT service ports, flags risky configurations, and produces a scored JSON risk report.

> **Only run this on networks you own or are explicitly authorized to assess.**

## The Problem

IoT devices (cameras, smart plugs, printers, hubs) often ship with unencrypted services, exposed remote access, and unverified firmware. This framework gives a quick, repeatable first look at what's exposed on a network and how risky it is.

## How It Works

```text
discovery.py  ──►  service_scanner.py  ──►  risk_engine.py  ──►  reporter.py
ping sweep         TCP connect checks       rule-based findings   JSON report +
(no root needed)   on common IoT ports      + 0–10 risk score     console summary
```

1. **Discovery** – Detects the local IP on the configured interface (macOS `ipconfig getifaddr`), then ping-sweeps the first 100 hosts of the /24 network. Reverse DNS is used for hostnames.
2. **Service scan** – TCP connect checks on ports 22, 80, 443, 1883, 5683, 8080, 554, 5000, and 1900.
3. **Risk engine** – Applies these rules:

| Finding | Trigger | Severity | CVSS-style score |
|---|---|---|---|
| Unencrypted HTTP | HTTP open, 443 closed | High | 7.5 |
| Plaintext MQTT | Port 1883 open | High | 7.5 |
| Excessive exposure | More than 3 open ports | Medium | 6.1 |
| Remote access exposed | SSH open | Medium | 5.9 |
| Unverified IoT device | Every device (baseline) | Low | 3.1 |

   Overall score = `min(average finding score × 0.8 + open ports × 0.4, 10)`. Rating: ≥ 8 Critical, ≥ 6 High, ≥ 4 Medium, otherwise Low.

4. **Reporter** – Writes `reports/iot_security_report_<timestamp>.json` and prints a summary.

## Setup

```bash
git clone https://github.com/chloe071/iot-security-framework.git
cd iot-security-framework
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Edit `config/config.yaml` to set your network interface (default `en0` on macOS).

## Usage

```bash
python main.py            # uses config/config.yaml
python main.py --verbose  # debug logging
python main.py --config path/to/other.yaml
```

## Sample Output

```json
{
  "timestamp": "2026-04-13T12:11:33.348212",
  "total_devices": 5,
  "critical": 0,
  "high": 0,
  "assessments": [
    { "ip": "100.69.36.1", "score": 2.88, "severity": "LOW", "vulns": 1 }
  ]
}
```

Full example reports from test runs are in [`reports/`](reports/).

## Results

In my test runs (April 2026) the tool discovered 5 devices on my test network. All were rated **Low** risk, with only the baseline "unverified device" finding — no plaintext MQTT, exposed HTTP, or SSH was detected.

## Running Tests

```bash
pip install pytest
pytest -q
```

Unit tests cover the risk rules and confirm the score is capped at 10.

## Limitations

- Discovery relies on macOS `ipconfig`; other systems fall back to `192.168.1.0/24`.
- Only the first 100 hosts of a /24 are scanned; devices that block ping are missed.
- Port checks confirm a port is open but don't fingerprint the service or version.
- Findings are rule-based; scores are CVSS-style estimates, not official CVSS calculations.
- `subnet`, `timeout`, and `common_ports` in `config.yaml` are not yet used by the scanner.

## Planned Improvements

- Use the config file's subnet and port list
- Service/version fingerprinting (e.g., nmap)
- Default-credential checks for common devices
- HTML report output
