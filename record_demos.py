"""Run genuine, authorized scans against controlled 127.0.0.1 lab services.

This is the ONLY way bundled example scan JSON should be regenerated.
"""
import json
from pathlib import Path
from demo_lab import lab_servers
from vulnscope.scanner import run_scan

SAMPLES = Path(__file__).parent / "samples"
CASES = {
    "lab-01-missing-headers": "8765",
    "lab-02-header-hardened": "8766",
    "lab-03-local-redirect": "8767",
    "lab-04-self-signed-tls": "8768",
    "lab-05-multi-port-assessment": "8765-8770",
}


def main() -> None:
    SAMPLES.mkdir(exist_ok=True)
    with lab_servers():
        for name, ports in CASES.items():
            result = run_scan("127.0.0.1", ports, acknowledged=True)
            result["kind"] = "recorded-local-lab-scan"
            result["source_note"] = "Captured by record_demos.py against controlled loopback lab; not live."
            result["demo_case"] = name
            output = SAMPLES / f"{name}.json"
            output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"Recorded {name}: {len(result['findings'])} findings; {len(result['ports'])} ports")


if __name__ == "__main__":
    main()
