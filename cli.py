"""Optional command line interface (scanner and reports)."""
import argparse
from pathlib import Path
from vulnscope.scanner import run_scan
from vulnscope.reporting import json_report, csv_report, html_report


def main():
    parser = argparse.ArgumentParser(description="VulnScope authorized local assessment")
    parser.add_argument("--target", default="127.0.0.1", help="Exact allowlisted IP, or localhost")
    parser.add_argument("--ports", default="8765,8766,8767,8768")
    parser.add_argument("--authorized", action="store_true", help="I confirm ownership or explicit permission")
    parser.add_argument("--output", default="reports", help="Output folder (gitignored by default)")
    args = parser.parse_args()
    result = run_scan(args.target, args.ports, args.authorized)
    path = Path(args.output)
    path.mkdir(parents=True, exist_ok=True)
    for name, data in (("assessment.json", json_report(result)), ("findings.csv", csv_report(result)), ("assessment.html", html_report(result))):
        (path / name).write_bytes(data)
    print(f"Target {result['target']}: {len(result['ports'])} ports, {len(result['findings'])} findings")
    print(f"Reports saved to {path.resolve()}")


if __name__ == "__main__":
    main()
