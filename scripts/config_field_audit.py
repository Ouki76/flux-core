#!/usr/bin/env python3
"""Find configuration fields that are accepted but never consumed.

A field that parses and is then ignored is the worst kind of bug in a proxy: the
user believes a feature is configured while it silently does nothing. This scans
`crates/flux-app/src/config.rs` for `pub <field>:` declarations and reports any
whose name never appears in a non-declaration line anywhere in the workspace.

Run: python3 scripts/config_field_audit.py
Exit code 1 when a suspicious field is found.
"""

# WHAT IT CATCHES: a field that nothing reads at all — the class where a config key
# is accepted and has no effect. It ignores the `Config::merge` body and destructuring
# patterns with `..`, because copying a value from an included file or binding it and
# dropping it is bookkeeping, not consumption.
#
# WHAT IT CANNOT CATCH, by construction: a field that is read, forwarded into a
# lower-layer config struct, and then ignored by that layer. `tuic.congestion_control`
# is the canonical example — it is read here and placed into `TuicV5Config`, and the
# TUIC outbound never looks at it. Finding that needs a semantic check per field, not
# a text scan; `Config::validate` refuses the unimplemented cases instead, which is why
# this script passing is necessary but not sufficient.

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

    # Lines inside `Config::merge` do not count as consumption: merging a field
    # from an included file into the main config, or testing `is_some()` on it, is
    # bookkeeping — the field still has no effect on behaviour if nothing else
    # reads it. That distinction is exactly the false negative that let an inert
    # field pass this check.
    merge_lines: set[tuple[str, int]] = set()
    for path, text in corpus:
        lines = text.splitlines()
        in_merge = False
        depth = 0
        for idx, line in enumerate(lines):
            if not in_merge and re.search(r"fn merge\b", line):
                in_merge = True
                depth = 0
            if in_merge:
                depth += line.count("{") - line.count("}")
                merge_lines.add((str(path), idx))
                if depth <= 0 and "}" in line:
                    in_merge = False

    suspicious = []
    for field in fields:
        decl = re.compile(rf"^\s{{4,8}}pub {re.escape(field)}: ", re.M)
        # A field is *consumed* only when something reads it. Merely naming it is
        # not enough: a field copied from one config into another (`self.x =
        # other.x`) and never read afterwards is exactly the "accepted and
        # silently ignored" defect this script exists to catch — and the previous
        # version counted that as a hit, so it reported every field as consumed.
        read_patterns = [
            # `.field` used as a value (not as an assignment target)
            re.compile(rf"\.{re.escape(field)}\b(?!\s*=(?!=))"),
            # `field: <expr>` in a struct literal where the value is not just a copy
            re.compile(rf"\b{re.escape(field)}\s*:\s*(?!self\.{re.escape(field)}\b|other\.{re.escape(field)}\b)"),
        ]
        hits = 0
        for path, text in corpus:
            for idx, line in enumerate(text.splitlines()):
                if (str(path), idx) in merge_lines:
                    continue
                stripped = line.strip()
                if decl.match(line) or decl.match("    " + line.lstrip()):
                    continue
                # Assignments that merely move the value around are not uses.
                if re.match(rf"^self\.{re.escape(field)}\s*=\s*(other|\w+)\.{re.escape(field)}\s*;$", stripped):
                    continue
                # A destructuring pattern with `..` (`Config::X { field, .. }`)
                # binds the field and then throws it away — that is not a use.
                window = "\n".join(text.splitlines()[idx : idx + 4])
                if re.search(rf"\{{[^}}]*\b{re.escape(field)}\b[^}}]*\.\.", window):
                    continue
                if any(p.search(line) for p in read_patterns):
                    hits += 1
        if hits == 0:
            suspicious.append(field)

    print(f"scanned {len(fields)} config fields")
    if not suspicious:
        print("OK: every field is consumed somewhere")
        return 0
    print(f"\nfields with no consumer ({len(suspicious)}):")
    for field in suspicious:
        print(f"  - {field}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
