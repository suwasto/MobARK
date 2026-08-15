#!/usr/bin/env python3
"""Vendor OWASP MASTG data into the MobARK repo.

Downloads the OWASP/owasp-mastg tarball at a pinned ref and writes:

  backend/app/analysis/resources/mastg_mapping.json   (test front matter)
  backend/app/analysis/rules/mastg/*.yml              (MASTG semgrep rules)

The mapping JSON records ``source_ref`` / ``source_date`` so staleness is
auditable. Re-run periodically (or in CI) with a newer ref to stay in sync.

Usage:
  python scripts/sync_mastg.py                # use the recorded last ref
  python scripts/sync_mastg.py --ref <sha|tag> --dry-run
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tarfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install PyYAML")

BACKEND = Path(__file__).resolve().parents[1]
MAPPING_OUT = BACKEND / "app" / "analysis" / "resources" / "mastg_mapping.json"
RULES_OUT = BACKEND / "app" / "analysis" / "rules" / "mastg"

DEFAULT_REF = "master"
TEST_RE = re.compile(r"^(tests|tests-beta)/(android|ios)/.*/MASTG-TEST-\d{4}\.md$")
RULE_RE = re.compile(r"^rules/mastg-android-.*\.ya?ml$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def resolve_ref(ref: str) -> str:
    """Resolve a branch/tag to a commit SHA so the vendored ref is pinned."""
    if _SHA_RE.fullmatch(ref):
        return ref
    url = f"https://api.github.com/repos/OWASP/owasp-mastg/commits/{ref}"
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310
        return json.load(resp)["sha"]


def fetch_tarball(ref: str) -> bytes:
    url = f"https://codeload.github.com/OWASP/owasp-mastg/tar.gz/{ref}"
    print(f"fetching {url}")
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310
        return resp.read()


def extract(data: bytes) -> list[tuple[str, bytes]]:
    """Return (relative_path, content) for the files we care about."""
    wanted: list[tuple[str, bytes]] = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            rel = "/".join(member.name.split("/")[1:])  # strip top-level dir
            if TEST_RE.match(rel) or RULE_RE.match(rel):
                f = tar.extractfile(member)
                if f is not None:
                    wanted.append((rel, f.read()))
    return wanted


def parse_front_matter(path: str, content: bytes) -> dict | None:
    text = content.decode("utf-8", "replace")
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    try:
        fm = yaml.safe_load(text[3:end]) or {}
    except yaml.YAMLError:
        return None
    test_id = (fm.get("id") or Path(path).stem).upper()
    return {
        test_id: {
            "platform": fm.get("platform"),
            "title": fm.get("title"),
            "status": fm.get("status"),
            "masvs_v2_id": _as_list(fm.get("masvs_v2_id")),
            "masvs_v1_id": _as_list(fm.get("masvs_v1_id")),
        }
    }


def _as_list(value) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else [str(v) for v in value]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default=DEFAULT_REF, help="upstream ref (branch, tag, or SHA)")
    parser.add_argument("--dry-run", action="store_true", help="print summary without writing")
    args = parser.parse_args()

    pinned = resolve_ref(args.ref)
    print(f"pinned ref {args.ref!r} -> {pinned}")
    data = fetch_tarball(pinned)
    files = extract(data)

    tests: dict[str, dict] = {}
    rules: dict[str, bytes] = {}
    for rel, content in files:
        if RULE_RE.match(rel):
            rules[Path(rel).name] = content
        elif TEST_RE.match(rel):
            parsed = parse_front_matter(rel, content)
            if parsed:
                tests.update(parsed)

    if not tests and not rules:
        print(f"nothing extracted for ref {args.ref!r} - check the ref", file=sys.stderr)
        return 1

    mapping = {
        "source_ref": pinned,
        "source_date": datetime.now(UTC).date().isoformat(),
        "generated_at": datetime.now(UTC).isoformat(),
        "test_count": len(tests),
        "rule_count": len(rules),
        "tests": tests,
    }

    if args.dry_run:
        print(json.dumps(mapping, indent=2)[:4000])
        print(f"[dry-run] would write {len(tests)} tests and {len(rules)} rules")
        return 0

    MAPPING_OUT.parent.mkdir(parents=True, exist_ok=True)
    MAPPING_OUT.write_text(json.dumps(mapping, indent=2, sort_keys=False) + "\n")
    RULES_OUT.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(rules.items()):
        (RULES_OUT / name).write_bytes(content)
    (RULES_OUT / "SOURCE.txt").write_text(
        f"Vendored from OWASP/owasp-mastg @ {pinned} ({datetime.now(UTC).date().isoformat()})\n"
    )
    print(f"wrote {MAPPING_OUT} ({len(tests)} tests)")
    print(f"wrote {len(rules)} rules to {RULES_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
