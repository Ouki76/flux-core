#!/usr/bin/env python3
"""Find configuration fields that are accepted but never consumed.

A field that parses and is then ignored is the worst kind of bug in a proxy: the
user believes a feature is configured while it silently does nothing. This scans
`crates/flux-app/src/config.rs` for `pub <field>:` declarations and reports any
whose name never appears in a non-declaration line anywhere in the workspace.

Run: python3 scripts/config_field_audit.py
Exit code 1 when a suspicious field is found.
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / "crates/flux-app/src/config.rs"


def main() -> int:
    src = CONFIG.read_text()
    fields = sorted(
        {
            m.group(1)
            for m in re.finditer(r"^\s{4,8}pub (\w+): ", src, re.M)
        }
    )

    corpus = []
    for path in list(ROOT.glob("crates/**/*.rs")) + list(ROOT.glob("src/**/*.rs")):
        corpus.append((path, path.read_text(errors="ignore")))

    suspicious = []
    for field in fields:
        decl = re.compile(rf"^\s{{4,8}}pub {re.escape(field)}: ", re.M)
        use = re.compile(rf"(?:\.{re.escape(field)}\b|\b{re.escape(field)}\s*:|'{re.escape(field)}'|\"{re.escape(field)}\")")
        hits = 0
        for _path, text in corpus:
            for line in text.splitlines():
                if decl.match(line) or decl.match("    " + line.lstrip()):
                    continue
                if use.search(line):
                    hits += 1
        if hits == 0:
            suspicious.append(field)

    print(f"scanmed {len(fields)} config fields")
    if not suspicious:
        print("OK: every field is consumed somewhere")
        return 0
    print(f"\nfields with no consumer ({len(suspicious)}):")
    for field in suspicious:
        print(f"  - {field}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
