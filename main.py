#!/usr/bin/env python3
"""Run the IoT assessment only on networks you are authorized to assess."""
import argparse
import logging
import os
from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent
logger = logging.getLogger(__name__)


def load_config(path):
    import yaml
    with path.open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict):
        raise ValueError("Configuration must be a YAML mapping")
    network = config.get("network")
    if not isinstance(network, dict):
        raise ValueError("Configuration requires a network mapping")
    interface = network.get("interface")
    if not isinstance(interface, str) or not interface.strip():
        raise ValueError("network.interface must be a non-empty string")
    network["interface"] = interface.strip()
    return config


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=BASE_DIR / "config" / "config.yaml")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)
    config_path = args.config.resolve()
    original_cwd = Path.cwd()
    try:
        config = load_config(config_path)
        sys.path.insert(0, str(BASE_DIR / "src"))
        from discovery import DeviceDiscovery
        from service_scanner import ServiceScanner
        from risk_engine import RiskEngine
        from reporter import Reporter

        # Existing modules use relative paths; keep them anchored to the project.
        os.chdir(BASE_DIR)
        interface = config["network"]["interface"]
        logger.info("Discovering devices on interface %s", interface)
        devices = DeviceDiscovery(interface).discover()
        logger.info("Found %s device(s)", len(devices))
        if not devices:
            logger.info("No devices discovered; no assessment report generated")
            return 0
        scanner = ServiceScanner()
        for device in devices:
            scanner.scan_device(device)
        engine = RiskEngine()
        assessments = [engine.assess(device) for device in devices]
        Reporter().generate_reports(devices, assessments)
        return 0
    except KeyboardInterrupt:
        logger.warning("Assessment interrupted")
        return 130
    except Exception as exc:
        logger.error("Assessment failed: %s", exc, exc_info=args.verbose)
        return 1
    finally:
        os.chdir(original_cwd)


if __name__ == "__main__":
    raise SystemExit(main())
