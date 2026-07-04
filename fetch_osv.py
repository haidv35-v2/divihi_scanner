#!/usr/bin/env python3
"""
fetch_osv.py — download the OSV/GHSA vulnerability database for offline use.

Source: the official OSV.dev bucket (no auth, plain HTTPS). Each ecosystem is a
single `all.zip` of OSV-format JSON records. OSV already ingests the GitHub
Advisory Database (GHSA), so this covers both.

    https://osv-vulnerabilities.storage.googleapis.com/{ECOSYSTEM}/all.zip

Usage:
    python fetch_osv.py                     # PyPI npm Packagist -> ./osv-db
    python fetch_osv.py PyPI npm Go -o ./osv-db
    python fetch_osv.py --list              # print known ecosystems

Then point the scanner at it:
    python scanner.py ./src --osv-db ./osv-db

Dependency-free (urllib + zipfile).
"""
from __future__ import annotations

import argparse
import io
import os
import sys
import urllib.error
import urllib.request
import zipfile

BASE = "https://osv-vulnerabilities.storage.googleapis.com"

# Map our manifest ecosystems to OSV bucket names (they match, listed for help).
KNOWN = [
    "PyPI", "npm", "Packagist", "Go", "RubyGems", "Maven", "NuGet",
    "crates.io", "Pub", "Hex", "Hackage", "Bitnami", "Alpine", "Debian",
    "Ubuntu", "GitHub Actions", "SwiftURL", "Linux",
]

DEFAULT = ["PyPI", "npm", "Packagist"]


def fetch_ecosystem(eco: str, outdir: str, timeout: int = 120) -> int:
    """Download and extract one ecosystem's all.zip. Returns #records written."""
    url = f"{BASE}/{urllib.request.quote(eco)}/all.zip"
    dest = os.path.join(outdir, eco.replace("/", "_"))
    os.makedirs(dest, exist_ok=True)
    print(f"  {eco:<16} downloading {url}", file=sys.stderr)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ai-vuln-harness"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            blob = resp.read()
    except urllib.error.HTTPError as e:
        print(f"  {eco:<16} HTTP {e.code} (unknown ecosystem?) -- skipped",
              file=sys.stderr)
        return 0
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"  {eco:<16} download failed: {e} -- skipped", file=sys.stderr)
        return 0
    n = 0
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                data = zf.read(name)
                with open(os.path.join(dest, os.path.basename(name)), "wb") as fh:
                    fh.write(data)
                n += 1
    except zipfile.BadZipFile:
        print(f"  {eco:<16} bad zip -- skipped", file=sys.stderr)
        return 0
    size_mb = len(blob) / 1_048_576
    print(f"  {eco:<16} {n} advisories  ({size_mb:.1f} MB)  -> {dest}",
          file=sys.stderr)
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ecosystems", nargs="*", default=[],
                    help=f"OSV ecosystems (default: {' '.join(DEFAULT)})")
    ap.add_argument("-o", "--out", default="osv-db", help="Output directory")
    ap.add_argument("--list", action="store_true",
                    help="List known ecosystem names and exit")
    ap.add_argument("--timeout", type=int, default=120)
    a = ap.parse_args(argv)

    if a.list:
        print("Known OSV ecosystems (case-sensitive):")
        for e in KNOWN:
            print(" ", e)
        print("\nFull list: https://osv-vulnerabilities.storage.googleapis.com/"
              "ecosystems.txt")
        return 0

    ecosystems = a.ecosystems or DEFAULT
    os.makedirs(a.out, exist_ok=True)
    print(f"Fetching {len(ecosystems)} ecosystem(s) into {a.out}/",
          file=sys.stderr)
    total = 0
    for eco in ecosystems:
        total += fetch_ecosystem(eco, a.out, a.timeout)
    print(f"Done. {total} advisories total in {os.path.abspath(a.out)}",
          file=sys.stderr)
    print(f"\nUse it:  python scanner.py ./src --osv-db {a.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
