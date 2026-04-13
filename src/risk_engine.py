from models import Device, Vulnerability, RiskAssessment, SeverityLevel

class RiskEngine:
    def assess(self, device):
        vulns = []

        if "HTTP" in device.protocols and 443 not in device.open_ports:
            vulns.append(Vulnerability(
                device_ip=device.ip_address, service="HTTP",
                vulnerability_type="unencrypted_http",
                description="HTTP running without HTTPS",
                severity=SeverityLevel.HIGH, cvss_score=7.5,
                remediation="Enable HTTPS/TLS on device"
            ))

        if 1883 in device.open_ports:
            vulns.append(Vulnerability(
                device_ip=device.ip_address, service="MQTT",
                vulnerability_type="mqtt_plaintext",
                description="MQTT on unencrypted port 1883",
                severity=SeverityLevel.HIGH, cvss_score=7.5,
                remediation="Migrate to MQTT-TLS on port 8883"
            ))

        if len(device.open_ports) > 3:
            vulns.append(Vulnerability(
                device_ip=device.ip_address, service="Network",
                vulnerability_type="excessive_exposure",
                description=str(len(device.open_ports)) + " open ports detected",
                severity=SeverityLevel.MEDIUM, cvss_score=6.1,
                remediation="Close unused ports via firewall"
            ))

        if "SSH" in device.protocols:
            vulns.append(Vulnerability(
                device_ip=device.ip_address, service="SSH",
                vulnerability_type="remote_access_exposed",
                description="SSH port 22 accessible - verify auth policy",
                severity=SeverityLevel.MEDIUM, cvss_score=5.9,
                remediation="Disable password auth, enforce key-based SSH only"
            ))

        vulns.append(Vulnerability(
            device_ip=device.ip_address, service="Device",
            vulnerability_type="unverified_iot_device",
            description="Device on network with unverified firmware/config",
            severity=SeverityLevel.LOW, cvss_score=3.1,
            remediation="Verify device firmware version and default credentials"
        ))

        avg = sum(v.cvss_score for v in vulns) / len(vulns)
        score = min(avg * 0.8 + len(device.open_ports) * 0.4, 10.0)

        if score >= 8.0:
            severity = SeverityLevel.CRITICAL
        elif score >= 6.0:
            severity = SeverityLevel.HIGH
        elif score >= 4.0:
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW

        return RiskAssessment(device.ip_address, round(score, 2), severity, vulns)