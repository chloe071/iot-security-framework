from datetime import datetime
import json
from pathlib import Path
from models import Device, RiskAssessment, SeverityLevel

class Reporter:
    def __init__(self):
        self.output_dir = Path("reports")
        self.output_dir.mkdir(exist_ok=True)

    def generate_reports(self, devices, assessments):
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_devices": len(devices),
            "critical": len([a for a in assessments if a.severity == SeverityLevel.CRITICAL]),
            "high": len([a for a in assessments if a.severity == SeverityLevel.HIGH]),
            "assessments": []
        }

        for a in assessments:
            report["assessments"].append({
                "ip": a.device_ip,
                "score": float(a.overall_risk_score),
                "severity": a.severity.value,
                "vulns": len(a.vulnerabilities)
            })

        filename = f"reports/iot_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        self._print_summary(assessments)
        print(f"📊 Full report: {filename}")

    def _print_summary(self, assessments):
        print("\n" + "="*70)
        print("🎯 RISK-BASED IOT SECURITY ASSESSMENT")
        print("="*70)

        critical = [a for a in assessments if a.severity == SeverityLevel.CRITICAL]
        high     = [a for a in assessments if a.severity == SeverityLevel.HIGH]
        medium   = [a for a in assessments if a.severity == SeverityLevel.MEDIUM]
        low      = [a for a in assessments if a.severity == SeverityLevel.LOW]

        print(f"📈 Total: {len(assessments)} | 🔴 Critical: {len(critical)} | 🟡 High: {len(high)} | 🔵 Medium: {len(medium)} | 🟢 Low: {len(low)}")
        print("-"*70)

        for a in assessments:
            if a.severity == SeverityLevel.CRITICAL:
                marker = "🔴"
            elif a.severity == SeverityLevel.HIGH:
                marker = "🟡"
            elif a.severity == SeverityLevel.MEDIUM:
                marker = "🔵"
            else:
                marker = "🟢"

            print(f"{marker} {a.device_ip:<18} Score: {a.overall_risk_score:>4.1f}/10   Vulns: {len(a.vulnerabilities)}   Severity: {a.severity.value}")
            for v in a.vulnerabilities:
                print(f"     ↳ [{v.severity.value:<8}] {v.vulnerability_type} (CVSS {v.cvss_score})")

        print("="*70)