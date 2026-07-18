"""Minimal persistence for scan results: one JSON file per scan on disk.

A small SOC tool doesn't need a database for this — file-backed storage is
enough to survive a process restart and keeps the deployment footprint tiny.
"""

import json
from pathlib import Path

from app.models import ScanResult


class ScanStore:
    def __init__(self, base_path: str):
        self._base_path = Path(base_path)
        self._base_path.mkdir(parents=True, exist_ok=True)

    def _path_for(self, scan_id: str) -> Path:
        return self._base_path / f"{scan_id}.json"

    def save(self, scan: ScanResult) -> None:
        self._path_for(scan.id).write_text(scan.model_dump_json(indent=2))

    def get(self, scan_id: str) -> ScanResult | None:
        path = self._path_for(scan_id)
        if not path.exists():
            return None
        return ScanResult.model_validate_json(path.read_text())

    def list_ids(self) -> list[str]:
        return [p.stem for p in self._base_path.glob("*.json")]
