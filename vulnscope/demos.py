"""Load only labeled, saved local-lab scan results from project assets."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parent.parent


def available_demos() -> list[Path]:
    return sorted((ROOT / "samples").glob("lab-*.json"))


def load_demo(path: Path) -> dict:
    if path.resolve() not in [item.resolve() for item in available_demos()]:
        raise ValueError("Not a packaged demo fixture")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("kind") != "recorded-local-lab-scan":
        raise ValueError("Missing historical demo provenance")
    return data
