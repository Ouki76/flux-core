#!/usr/bin/env bash
#
# Local validation for everything in this repository that no local toolchain can
# execute: the GitHub Actions workflows and the shell scripts they call.
#
# There is no `act`/`actionlint` on this machine (and nothing may be installed),
# so this is a deliberately small, dependency-light checker:
#
#   1. YAML parses, and has no duplicate keys (PyYAML silently keeps the last
#      one, GitHub silently uses... something — a duplicate `run:` is a bug).
#   2. Every job has `runs-on` and at least one step; every step has `uses:` or
#      `run:`.
#   3. Every `steps.<id>.outputs.*` / `steps.<id>.outcome` reference resolves to a
#      step that is actually defined in that job. This is the mistake that only
#      shows up as an empty string at runtime.
#   4. Every `run:` block that is a multi-line script is at least shell-parsable
#      (`bash -n`) after stripping the `${{ … }}` expressions.
#   5. Every `scripts/*.sh` parses with `bash -n`, and every referenced script
#      exists.
#
# What it does NOT do: resolve `uses:` versions, type-check `${{ }}` expressions,
# or emulate a runner. Those need GitHub's infrastructure or `actionlint`.
#
# Usage: scripts/check_workflows.sh [-q]
# Exit:  0 clean, 1 problems found, 2 missing prerequisite (python3)

set -uo pipefail

cd "$(dirname "$0")/.."

QUIET=0
[ "${1:-}" = "-q" ] && QUIET=1

problems=0
note() { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; problems=$((problems + 1)); }

command -v python3 >/dev/null 2>&1 || {
    echo "error: python3 is required (PyYAML parses the workflows)" >&2
    exit 2
}
if ! python3 -c 'import yaml' 2>/dev/null; then
    # PyYAML is not part of a minimal interpreter. On a developer machine that is
    # a hard error (fix it with `dnf install python3-pyyaml` / `apt install
    # python3-yaml`); on a runner it would be a build break nobody can act on from
    # the PR, so it is reported as an annotation and the remaining shell checks
    # still run.
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::warning::PyYAML is unavailable on this runner — YAML structure was not validated (shell checks still ran)"
    else
        echo "error: PyYAML is not importable by python3 — install python3-pyyaml (or pip install pyyaml)" >&2
        exit 2
    fi
fi

# --- 1-3: workflow structure ------------------------------------------------

note '== workflows =='
python3 - <<'PY'
import glob
import re
import sys

import yaml


class StrictLoader(yaml.SafeLoader):
    """Duplicate keys are an error: the second one silently wins at runtime."""


def _no_duplicates(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark)
        seen.add(key)
    return loader.construct_mapping(node, deep)


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates)

problems = 0
for path in sorted(glob.glob('.github/workflows/*.yml')):
    try:
        doc = yaml.load(open(path), Loader=StrictLoader)
    except yaml.YAMLError as exc:
        print(f"FAIL: {path}: {exc}", file=sys.stderr)
        problems += 1
        continue

    if not isinstance(doc, dict):
        print(f"FAIL: {path}: top level is not a mapping", file=sys.stderr)
        problems += 1
        continue

    # PyYAML resolves the `on:` key to the boolean True (YAML 1.1).
    if 'jobs' not in doc:
        print(f"FAIL: {path}: no `jobs:`", file=sys.stderr)
        problems += 1
        continue

    for job_name, job in (doc.get('jobs') or {}).items():
        where = f"{path}::{job_name}"
        if not isinstance(job, dict):
            print(f"FAIL: {where}: job is not a mapping", file=sys.stderr)
            problems += 1
            continue
        steps = job.get('steps') or []
        if not steps:
            print(f"FAIL: {where}: no steps", file=sys.stderr)
            problems += 1
        if not job.get('runs-on'):
            print(f"FAIL: {where}: no runs-on", file=sys.stderr)
            problems += 1
        ids = {s['id'] for s in steps if isinstance(s, dict) and 'id' in s}
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                print(f"FAIL: {where}: step {i} is not a mapping", file=sys.stderr)
                problems += 1
                continue
            if 'uses' not in step and 'run' not in step:
                print(f"FAIL: {where}: step {i} has neither `uses` nor `run`",
                      file=sys.stderr)
                problems += 1
            blob = yaml.dump(step)
            for ref in sorted(set(re.findall(r'steps\.([A-Za-z0-9_-]+)\.', blob))):
                if ref not in ids:
                    print(f"FAIL: {where}: step {i} references undefined "
                          f"`steps.{ref}`", file=sys.stderr)
                    problems += 1
            # A step `id` must not be repeated in the same job.
        if len(ids) != sum(1 for s in steps if isinstance(s, dict) and 'id' in s):
            print(f"FAIL: {where}: duplicate step id", file=sys.stderr)
            problems += 1

sys.exit(1 if problems else 0)
PY
[ $? -ne 0 ] && problems=$((problems + 1))

# --- 4: run blocks parse as shell ------------------------------------------

note '== run blocks =='
python3 - <<'PY' > /tmp/.flux_run_blocks.txt
import glob
import os
import re

import yaml

os.makedirs('/tmp/.flux_run_blocks', exist_ok=True)
n = 0
for path in sorted(glob.glob('.github/workflows/*.yml')):
    doc = yaml.safe_load(open(path))
    for job_name, job in (doc.get('jobs') or {}).items():
        for i, step in enumerate(job.get('steps') or []):
            script = step.get('run')
            if not isinstance(script, str):
                continue
            # Only POSIX/bash steps: `shell: python`/`pwsh` blocks would be
            # false positives here (and there are none today).
            shell = step.get('shell')
            if shell and shell not in ('bash', 'sh'):
                continue
            # Strip ${{ ... }} so the shell sees plausible syntax.
            body = re.sub(r'\$\{\{[^}]*\}\}', 'EXPR', script)
            out = f'/tmp/.flux_run_blocks/{n:03d}.sh'
            with open(out, 'w') as fh:
                fh.write(body + '\n')
            print(f"{out}\t{path}::{job_name} step {i} ({step.get('name', 'unnamed')})")
            n += 1
PY
while IFS=$'\t' read -r file label; do
    [ -n "${file:-}" ] || continue
    bash -n "$file" 2>/dev/null || fail "shell syntax in $label"
done < /tmp/.flux_run_blocks.txt
rm -rf /tmp/.flux_run_blocks /tmp/.flux_run_blocks.txt

# --- 5: scripts ------------------------------------------------------------

note '== scripts =='
for s in scripts/*.sh; do
    bash -n "$s" || fail "bash -n $s"
done

# Scripts invoked from workflows must exist.
python3 - <<'PY' > /tmp/.flux_script_refs.txt
import glob
import re

for path in sorted(glob.glob('.github/workflows/*.yml')):
    text = open(path).read()
    for ref in sorted(set(re.findall(r'(\./)?(scripts/[A-Za-z0-9_.-]+)', text))):
        print(f"{ref[1]}\t{path}")
PY
while IFS=$'\t' read -r script wf; do
    [ -n "${script:-}" ] || continue
    [ -e "$script" ] || fail "$wf references missing $script"
done < /tmp/.flux_script_refs.txt
rm -f /tmp/.flux_script_refs.txt

# --- verdict ---------------------------------------------------------------

if [ "$problems" -gt 0 ]; then
    printf '\n%d problem(s) found\n' "$problems" >&2
    exit 1
fi
note 'all checks passed'
exit 0