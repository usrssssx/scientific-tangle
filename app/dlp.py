from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT


DEFAULT_DLP_RULES_PATH = PROJECT_ROOT / "data" / "security" / "dlp_export_rules.json"
VALID_ACTIONS = {"flag", "approval_required", "block"}
VALID_CLASSIFICATIONS = {"public", "internal", "confidential", "secret"}


@dataclass(frozen=True)
class DlpRule:
    name: str
    description: str
    pattern: str
    action: str = "approval_required"
    classification: str = "confidential"
    formats: tuple[str, ...] = ("markdown", "csv", "pdf", "zip", "jsonld", "text/turtle")
    enabled: bool = True
    max_matches: int = 5


def _rule_from_dict(raw: dict[str, Any]) -> DlpRule:
    name = str(raw.get("name") or "").strip()
    pattern = str(raw.get("pattern") or "").strip()
    if not name or not pattern:
        raise ValueError("DLP rule requires name and pattern")
    action = str(raw.get("action") or "approval_required").strip()
    classification = str(raw.get("classification") or "confidential").strip()
    if action not in VALID_ACTIONS:
        raise ValueError(f"DLP rule {name} has invalid action: {action}")
    if classification not in VALID_CLASSIFICATIONS:
        raise ValueError(f"DLP rule {name} has invalid classification: {classification}")
    raw_formats = raw.get("formats") or ("markdown", "csv", "pdf", "zip", "jsonld", "text/turtle")
    if isinstance(raw_formats, str):
        formats = (raw_formats,)
    else:
        formats = tuple(str(item) for item in raw_formats)
    return DlpRule(
        name=name,
        description=str(raw.get("description") or name),
        pattern=pattern,
        action=action,
        classification=classification,
        formats=formats,
        enabled=bool(raw.get("enabled", True)),
        max_matches=max(1, int(raw.get("max_matches") or 5)),
    )


def _load_rules_payload() -> list[dict[str, Any]]:
    inline = os.getenv("RD_KG_DLP_RULES_JSON")
    if inline:
        payload = json.loads(inline)
    else:
        path = Path(os.getenv("RD_KG_DLP_RULES_PATH") or DEFAULT_DLP_RULES_PATH).expanduser()
        if not path.exists():
            return []
        payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = payload.get("rules", [])
    if not isinstance(payload, list):
        raise ValueError("DLP rules payload must be a list or an object with rules")
    return [item for item in payload if isinstance(item, dict)]


def load_dlp_rules() -> list[DlpRule]:
    return [_rule_from_dict(item) for item in _load_rules_payload()]


def _iter_text_values(value: Any, path: str = "$") -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        items: list[tuple[str, str]] = []
        for key, child in value.items():
            items.extend(_iter_text_values(child, f"{path}.{key}"))
        return items
    if isinstance(value, list):
        items = []
        for index, child in enumerate(value):
            items.extend(_iter_text_values(child, f"{path}[{index}]"))
        return items
    return []


def _format_matches(rule: DlpRule, export_format: str) -> bool:
    normalized = export_format.lower()
    return "*" in rule.formats or normalized in {item.lower() for item in rule.formats}


def inspect_export_payload(payload: Any, export_format: str, rules: list[DlpRule] | None = None) -> list[dict[str, Any]]:
    active_rules = [rule for rule in (rules if rules is not None else load_dlp_rules()) if rule.enabled and _format_matches(rule, export_format)]
    if not active_rules:
        return []
    text_values = _iter_text_values(payload)
    findings: list[dict[str, Any]] = []
    for rule in active_rules:
        regex = re.compile(rule.pattern, flags=re.IGNORECASE | re.MULTILINE)
        paths: list[str] = []
        match_count = 0
        for path, text in text_values:
            matches = list(regex.finditer(text))
            if not matches:
                continue
            match_count += len(matches)
            if len(paths) < rule.max_matches:
                paths.append(path)
        if match_count:
            findings.append(
                {
                    "rule": rule.name,
                    "description": rule.description,
                    "action": rule.action,
                    "classification": rule.classification,
                    "match_count": match_count,
                    "paths": paths,
                }
            )
    return findings
