"""Shared validation, findings, suppressions and reporting for defensive tools."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string with a timezone")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamps require a timezone")
    return result.astimezone(timezone.utc)


def object_value(value, label="input"):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def records(data, key, required=()):
    object_value(data)
    rows = data.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"{key} must be an array")
    for index, row in enumerate(rows):
        object_value(row, f"{key}[{index}]")
        if any(field not in row for field in required):
            raise ValueError(f"{key}[{index}] is missing required fields: {', '.join(required)}")
    return rows


def text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def boolean(value, label):
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def number(value, label, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{label} is outside the permitted range")
    return value


def string_list(value, label):
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} must be an array of non-empty strings")
    return value


def setting(policy, key, default, minimum=0, maximum=None):
    return number(policy.get(key, default), f"policy.{key}", minimum, maximum)


def finding(rule, severity, resource, title, evidence, remediation, **extra):
    if severity not in SEVERITIES:
        raise ValueError("unknown finding severity")
    resource = str(resource)
    stable = json.dumps([TOOL, rule, resource, extra.get("subject", "")], ensure_ascii=False)
    result = {"rule": rule, "severity": severity, "resource": resource,
              "title": title, "evidence": evidence, "remediation": remediation,
              "fingerprint": hashlib.sha256(stable.encode()).hexdigest()[:24]}
    result.update(extra)
    return result


def unique_rows(rows, key):
    result = {}
    for row in rows:
        identifier = text(row[key], key)
        if identifier in result:
            raise ValueError(f"duplicate {key} in inventory")
        result[identifier] = row
    return result


def decode_json(content):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("JSON contains a duplicate key")
            result[key] = value
        return result
    return json.loads(content, object_pairs_hook=reject_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON number")))


def load_json(path):
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("JSON input exceeds the 10 MiB limit")
    return decode_json(path.read_text(encoding="utf-8-sig"))


def build_report(findings, suppressions=(), now=None):
    now = now or datetime.now(timezone.utc)
    active, suppressed = [], []
    fingerprints = set()
    for suppression in suppressions:
        object_value(suppression, "suppression")
        text(suppression.get("fingerprint"), "suppression fingerprint")
        text(suppression.get("reason"), "suppression reason")
        timestamp(suppression.get("expires"))
        if suppression["fingerprint"] in fingerprints:
            raise ValueError("duplicate suppression fingerprint")
        fingerprints.add(suppression["fingerprint"])
    known = {item["fingerprint"]: item for item in suppressions
             if timestamp(item["expires"]) > now}
    for item in findings:
        if item["fingerprint"] in known:
            suppressed.append({**item, "suppression_reason": known[item["fingerprint"]]["reason"]})
        else:
            active.append(item)
    active.sort(key=lambda item: (-SEVERITIES[item["severity"]], item["resource"], item["rule"], item["fingerprint"]))
    return {"tool": TOOL, "version": VERSION, "generated_at": now.isoformat(),
            "summary": dict(Counter(item["severity"] for item in active)),
            "findings": active, "suppressed": suppressed}


def sarif(report):
    rules = {item["rule"]: item["title"] for item in report["findings"]}
    results = []
    for item in report["findings"]:
        results.append({"ruleId": item["rule"],
                        "level": "error" if SEVERITIES[item["severity"]] >= 3 else "warning" if SEVERITIES[item["severity"]] >= 1 else "note",
                        "message": {"text": item["title"] + ". " + item["remediation"]},
                        "locations": [{"logicalLocations": [{"name": item["resource"]}]}],
                        "partialFingerprints": {"securityToolFingerprint/v1": item["fingerprint"]},
                        "properties": {"severity": item["severity"], "evidence": item["evidence"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL, "version": VERSION,
                       "rules": [{"id": key, "shortDescription": {"text": title}} for key, title in sorted(rules.items())]}},
                       "results": results}]}


def markdown(report):
    def escape(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    lines = [f"# {TOOL} report", "", f"Version: {VERSION}. Findings: {len(report['findings'])}.", "",
             "| Severity | Resource | Finding | Recommended action |", "|---|---|---|---|"]
    for item in report["findings"]:
        lines.append("| " + " | ".join(escape(item[key]) for key in ("severity", "resource", "title", "remediation")) + " |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("input", nargs="?", type=Path, help="JSON inventory, event export or tool configuration")
    parser.add_argument("--demo", action="store_true", help="run the embedded synthetic example")
    parser.add_argument("--policy", type=Path, help="JSON object overriding documented defaults")
    parser.add_argument("--suppressions", type=Path, help="JSON array: fingerprint, reason, expires")
    parser.add_argument("--format", choices=["json", "sarif", "markdown"], default="json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=list(SEVERITIES), default="high")
    parser.add_argument("--now", help="timezone-aware ISO timestamp for reproducible reviews")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if args.demo == bool(args.input):
        parser.error("provide exactly one of input or --demo")
    try:
        now = timestamp(args.now) if args.now else datetime.now(timezone.utc)
        data = object_value(json.loads(json.dumps(DEMO)) if args.demo else load_json(args.input))
        policy = object_value(load_json(args.policy), "policy") if args.policy else {}
        suppressions = load_json(args.suppressions) if args.suppressions else []
        if not isinstance(suppressions, list):
            raise ValueError("suppressions must be an array")
        report = build_report(audit(data, policy, now), suppressions, now)
        content = markdown(report) if args.format == "markdown" else json.dumps(sarif(report) if args.format == "sarif" else report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            # Exclusive creation keeps earlier evidence from being overwritten.
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(content)
        else:
            print(content, end="")
        return int(any(SEVERITIES[item["severity"]] >= SEVERITIES[args.fail_on] for item in report["findings"]))
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        parser.exit(2, f"error: {type(exc).__name__}: {exc}\n")
import base64
import re
from pathlib import PurePosixPath

TOOL = "backup-restore-verifier"
DESCRIPTION = "Verify backup bytes, manifest coverage and snapshot age without restoring production data."
DEMO = {"snapshot_at": "2026-10-10T00:00:00Z", "critical_paths": ["database.snapshot", "configuration.json"],
        "manifest": [{"path": "database.snapshot", "sha256": "0" * 64, "size": 18}],
        "inline_files": {"database.snapshot": base64.b64encode(b"synthetic snapshot").decode()}}


def safe_relative(value):
    value = text(value, "manifest.path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value or ":" in value or value in {".", ""}:
        raise ValueError("manifest paths must be relative POSIX paths without traversal")
    return path


def file_digest(root, relative):
    path = root.joinpath(*relative.parts)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("backup path includes a symbolic link")
    if not path.resolve().is_relative_to(root):
        raise ValueError("backup path escapes the snapshot root")
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def audit(data, policy, now):
    object_value(data)
    snapshot_at = timestamp(data.get("snapshot_at"))
    if snapshot_at > now:
        raise ValueError("snapshot timestamp is in the future")
    rpo_hours = setting(policy, "rpo_hours", 24, 0.1)
    manifest = unique_rows(records(data, "manifest", ("path", "sha256", "size")), "path")
    critical = string_list(data.get("critical_paths"), "critical_paths")
    for value in critical:
        safe_relative(value)
    if "root" in data:
        root = Path(text(data["root"], "root")).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("snapshot root must be a directory")
        inline = None
    else:
        root = None
        inline = object_value(data.get("inline_files"), "inline_files")
    result = []
    age = (now - snapshot_at).total_seconds() / 3600
    if age > rpo_hours:
        result.append(finding("BACKUP-RPO", "high", "snapshot", "Snapshot exceeds the configured recovery-point target",
                              {"age_hours": round(age, 2), "rpo_hours": rpo_hours}, "Review backup freshness and the approved recovery-point objective."))
    for value in critical:
        if value not in manifest:
            result.append(finding("BACKUP-CRITICAL-COVERAGE", "high", value, "Critical file is absent from the manifest",
                                  {"manifest_entry": False}, "Verify backup scope and include the required recovery artifact."))
    for path_name, entry in manifest.items():
        relative = safe_relative(path_name)
        if not isinstance(entry["sha256"], str) or re.fullmatch(r"[a-fA-F0-9]{64}", entry["sha256"]) is None:
            raise ValueError("manifest requires a valid SHA-256 digest")
        expected_size = number(entry["size"], "manifest.size", 0)
        if not isinstance(expected_size, int):
            raise ValueError("manifest sizes must be integers")
        try:
            if root is not None:
                digest, size = file_digest(root, relative)
            else:
                if path_name not in inline:
                    raise FileNotFoundError(path_name)
                content = base64.b64decode(inline[path_name], validate=True)
                digest, size = hashlib.sha256(content).hexdigest(), len(content)
        except (OSError, ValueError) as exc:
            result.append(finding("BACKUP-UNVERIFIABLE", "high", path_name, "Backup artifact could not be verified",
                                  {"error_type": type(exc).__name__}, "Review missing, unreadable, malformed or symbolic-link artifacts."))
            continue
        if digest != entry["sha256"].lower() or size != expected_size:
            result.append(finding("BACKUP-INTEGRITY", "critical" if path_name in critical else "high", path_name,
                                  "Backup content differs from the trusted manifest", {"hash_matches": digest == entry["sha256"].lower(), "size_matches": size == expected_size},
                                  "Protect the snapshot and verify a trusted independent manifest before a recovery exercise."))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
