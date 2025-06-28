#!/usr/bin/env python3
"""
Secret-Hunter: tiny credential scanner for source trees.
Looks for the most common patterns that should never be committed to a repo.
"""

import re, sys, pathlib

# Regexes for a few high-value secrets (add more if you wish)
PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API key": re.compile(r"[A-Za-z0-9_]{32,}"),
    "Private key header": re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
    "Password in code": re.compile(r'pass(word)?\s*=\s*["\'].*?["\']', re.IGNORECASE),
}

def scan_file(path: pathlib.Path):
    """Yield (line_no, name, match_text) for each secret found in one file."""
    try:
        for i, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            for name, rx in PATTERNS.items():
                m = rx.search(line)
                if m:
                    yield i, name, m.group(0)[:50]  # redacted preview
    except (UnicodeDecodeError, PermissionError):
        pass  # skip binary or unreadable files

def main(root="."):
    root_path = pathlib.Path(root)
    findings = 0
    for path in root_path.rglob("*.*"):
        if path.is_file():
            for line_no, kind, snippet in scan_file(path):
                findings += 1
                print(f"[{kind:18}] {path}:{line_no} -> {snippet}")
    if findings == 0:
        print("No secrets found ✓")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
