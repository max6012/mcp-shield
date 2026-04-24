"""Core regex pattern matching engine for MCP Shield."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class PatternDef:
    """Definition of a single detection pattern."""

    name: str
    description: str
    regex: str
    severity: str  # "low", "medium", "high", "critical"
    category: str


@dataclass(frozen=True)
class Match:
    """A single match produced by the scanner."""

    pattern_name: str
    matched_text: str
    start: int
    end: int
    severity: str
    category: str


class Scanner:
    """Loads patterns from a YAML file and scans text for matches."""

    def __init__(self, patterns_path: str | Path) -> None:
        self.patterns: list[PatternDef] = []
        self._compiled: list[tuple[PatternDef, re.Pattern[str]]] = []

        raw = yaml.safe_load(Path(patterns_path).read_text())
        if not isinstance(raw, list):
            raise ValueError("Patterns YAML must be a list of pattern dicts")

        for entry in raw:
            pdef = PatternDef(
                name=entry["name"],
                description=entry["description"],
                regex=entry["regex"],
                severity=entry["severity"],
                category=entry["category"],
            )
            self.patterns.append(pdef)
            self._compiled.append((pdef, re.compile(pdef.regex)))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, text: str) -> list[Match]:
        """Run all compiled patterns against *text* and return matches."""
        matches: list[Match] = []
        for pdef, compiled in self._compiled:
            for m in compiled.finditer(text):
                matches.append(
                    Match(
                        pattern_name=pdef.name,
                        matched_text=m.group(),
                        start=m.start(),
                        end=m.end(),
                        severity=pdef.severity,
                        category=pdef.category,
                    )
                )
        return matches

    def scan_json(self, data: dict | list | str, _path: str = "") -> list[Match]:
        """Recursively walk a JSON-like structure and scan all string values.

        Each returned ``Match`` has its ``pattern_name`` prefixed with the
        JSON path to the value that triggered it (e.g. ``"args.query"``).
        """
        matches: list[Match] = []

        if isinstance(data, str):
            for m in self.scan(data):
                prefix = f"{_path}: " if _path else ""
                matches.append(
                    Match(
                        pattern_name=f"{prefix}{m.pattern_name}",
                        matched_text=m.matched_text,
                        start=m.start,
                        end=m.end,
                        severity=m.severity,
                        category=m.category,
                    )
                )
        elif isinstance(data, dict):
            for key, value in data.items():
                child_path = f"{_path}.{key}" if _path else key
                matches.extend(self.scan_json(value, _path=child_path))
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                child_path = f"{_path}[{idx}]" if _path else f"[{idx}]"
                matches.extend(self.scan_json(item, _path=child_path))

        return matches
