#!/usr/bin/env python3
"""Validate release identity and evidence before creating even a draft release."""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
VERSION_PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(dev|alpha|beta|rc)\.(0|[1-9][0-9]*))?")


def parse_version(version):
    match = VERSION_PATTERN.fullmatch(version)
    if not match:
        raise ValueError("Use MAJOR.MINOR.PATCH[-dev.N|-alpha.N|-beta.N|-rc.N]")
    stage = match[4] or "stable"
    if stage in {"alpha", "beta", "rc"} and int(match[5]) < 1:
        raise ValueError("Public prerelease sequence numbers start at 1")
    return stage


def validate_release(version, tag, commit, evidence, policy):
    stage = parse_version(version)
    if tag != "v" + version:
        raise ValueError("Release tag must exactly match VERSION")
    if stage == "dev":
        raise ValueError("Development snapshots cannot be published as releases")
    if evidence.get("version") != version or evidence.get("commit") != commit:
        raise ValueError("Evidence must identify this exact version and commit")
    failures = []
    for name in policy["stages"][stage]:
        gate = evidence.get("gates", {}).get(name, {})
        if gate.get("status") != "passed" or not gate.get("evidence"):
            failures.append(name)
    if failures:
        raise ValueError("Release gates not satisfied: " + ", ".join(failures))
    return stage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        version = (ROOT / "VERSION").read_text().strip()
        stage = validate_release(version, args.tag, args.commit, json.loads(args.evidence.read_text()),
                                 json.loads((ROOT / "release/policy.json").read_text()))
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Release refused: {exc}\n")
    print(json.dumps({"version": version, "stage": stage, "prerelease": stage != "stable"}))


if __name__ == "__main__":
    main()
