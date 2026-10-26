import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from models import Device
from risk_engine import RiskEngine


def make(ports, protocols):
    d = Device(ip_address="192.0.2.10")
    d.open_ports, d.protocols = list(ports), list(protocols)
    return d


def test_baseline_device_gets_one_low_finding():
    r = RiskEngine().assess(make([], []))
    assert len(r.vulnerabilities) == 1


def test_plaintext_mqtt_is_flagged():
    r = RiskEngine().assess(make([1883], ["MQTT"]))
    assert any(v.vulnerability_type == "mqtt_plaintext" for v in r.vulnerabilities)


def test_http_without_https_is_flagged():
    r = RiskEngine().assess(make([80], ["HTTP"]))
    assert any(v.vulnerability_type == "unencrypted_http" for v in r.vulnerabilities)


def test_score_capped_at_10():
    ports = [22, 80, 1883, 5683, 8080, 554, 5000, 1900]
    r = RiskEngine().assess(make(ports, ["HTTP", "SSH", "MQTT"]))
    assert r.overall_risk_score <= 10.0
