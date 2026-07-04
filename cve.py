#!/usr/bin/env python3
"""
cve.py — offline (and optional online) CVE lookup for dependencies, using the
OSV / GHSA data model (https://ossf.github.io/osv-schema/).

Offline mode (default, air-gapped friendly):
    Point --osv-db at a directory of OSV JSON records. You can populate it from
    the public OSV dumps, e.g.:
        gsutil -m cp -r "gs://osv-vulnerabilities/PyPI"      ./osv-db/
        gsutil -m cp -r "gs://osv-vulnerabilities/npm"       ./osv-db/
        gsutil -m cp -r "gs://osv-vulnerabilities/Packagist" ./osv-db/
    (each ecosystem is a folder of <id>.json files). Nested dirs are fine.

Online mode (--osv-online): queries https://api.osv.dev/v1/query per package.
Use only when you are allowed to send package names off-box.

No third-party dependencies.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

# manifest filename -> OSV ecosystem name
ECOSYSTEM_BY_MANIFEST = {
    "package.json": "npm",
    "composer.json": "Packagist",
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "go.mod": "Go",
    "Gemfile.lock": "RubyGems",
}


@dataclass
class Vuln:
    id: str
    summary: str
    severity: str
    fixed: str = ""

    def short(self) -> str:
        sev = f"{self.severity} " if self.severity else ""
        fix = f", fixed in {self.fixed}" if self.fixed else ""
        s = self.summary[:120] + ("..." if len(self.summary) > 120 else "")
        return f"{self.id} ({sev.strip()}{fix}): {s}"


# --------------------------------------------------------------------------- #
# Version comparison (numeric semver / PEP440-ish, best effort)
# --------------------------------------------------------------------------- #

def _ver_tuple(v: str) -> tuple[int, ...]:
    v = v.strip().lstrip("vV")
    # strip pre-release / build metadata for a stable numeric compare
    v = re.split(r"[-+]", v, 1)[0]
    parts = re.split(r"[._]", v)
    out: list[int] = []
    for p in parts:
        m = re.match(r"(\d+)", p)
        out.append(int(m.group(1)) if m else 0)
    return tuple(out) or (0,)


def cmp_ver(a: str, b: str) -> int:
    ta, tb = _ver_tuple(a), _ver_tuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def version_in_range(version: str, range_str: str) -> bool:
    """Match a version against a comma-joined constraint list.

    Handles GHSA-style ranges like ">= 1.0.0, < 1.2.3", "< 2.0.0", "= 1.2.3".
    """
    version = version or "0"
    parts = [p.strip() for p in range_str.split(",") if p.strip()]
    if not parts:
        return False
    for p in parts:
        m = re.match(r"(>=|<=|==|=|>|<)?\s*(.+)", p)
        if not m:
            continue
        op = m.group(1) or "="
        c = cmp_ver(version, m.group(2).strip())
        if op == ">=" and c < 0:
            return False
        if op == ">" and c <= 0:
            return False
        if op == "<=" and c > 0:
            return False
        if op == "<" and c >= 0:
            return False
        if op in ("=", "==") and c != 0:
            return False
    return True


def _affected_by_range(version: str, events: list[dict]) -> bool:
    """OSV range walk: events are ordered introduced/fixed/last_affected."""
    affected = False
    fixed_at = ""
    for ev in events:
        if "introduced" in ev:
            intro = ev["introduced"]
            if intro == "0" or cmp_ver(version, intro) >= 0:
                affected = True
        elif "fixed" in ev:
            if cmp_ver(version, ev["fixed"]) >= 0:
                affected = False
            fixed_at = ev["fixed"]
        elif "last_affected" in ev:
            if cmp_ver(version, ev["last_affected"]) > 0:
                affected = False
    return affected, fixed_at


def _record_matches(rec: dict, name: str, version: str) -> tuple[bool, str]:
    name_l = name.lower()
    fixed = ""
    for aff in rec.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("name", "").lower() != name_l:
            continue
        # explicit version list
        if version and version in (aff.get("versions") or []):
            return True, ""
        for rng in aff.get("ranges", []):
            hit, f = _affected_by_range(version or "0", rng.get("events", []))
            if hit:
                return True, f
            fixed = fixed or f
        # No ranges/versions info => treat as affected (conservative).
        if not aff.get("ranges") and not aff.get("versions"):
            return True, ""
    return False, fixed


def _extract_vuln(rec: dict, fixed: str) -> Vuln:
    ident = rec.get("id", "")
    aliases = rec.get("aliases", []) or []
    cve = next((a for a in aliases if a.startswith("CVE-")), "")
    display = cve or ident
    if cve and ident and cve != ident:
        display = f"{cve} ({ident})"
    sev = rec.get("database_specific", {}).get("severity", "")
    if not sev:
        for s in rec.get("severity", []) or []:
            if "CRITICAL" in str(s.get("score", "")).upper():
                sev = "CRITICAL"
    return Vuln(id=display, summary=rec.get("summary", "") or
                rec.get("details", "")[:160], severity=sev, fixed=fixed)


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #

class OsvDatabase:
    def __init__(self, *, online: bool = False, timeout: int = 15):
        self.online = online
        self.timeout = timeout
        # index: (ecosystem_lower, name_lower) -> list[record]
        self.index: dict[tuple[str, str], list[dict]] = {}
        self._online_cache: dict[tuple[str, str, str], list[Vuln]] = {}
        self.loaded = 0

    # --- offline loading ------------------------------------------------ #
    def load_dir(self, path: str) -> int:
        if not path or not os.path.isdir(path):
            return 0
        for dirpath, _dirs, files in os.walk(path):
            for fn in files:
                if not fn.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(dirpath, fn), encoding="utf-8") as fh:
                        rec = json.load(fh)
                except (OSError, json.JSONDecodeError):
                    continue
                for aff in rec.get("affected", []):
                    pkg = aff.get("package", {})
                    eco = pkg.get("ecosystem", "").split(":")[0].lower()
                    nm = pkg.get("name", "").lower()
                    if eco and nm:
                        self.index.setdefault((eco, nm), []).append(rec)
                        self.loaded += 1
        return self.loaded

    # --- query ---------------------------------------------------------- #
    def vulns_for(self, ecosystem: str, name: str, version: str) -> list[Vuln]:
        eco = ecosystem.split(":")[0].lower()
        out: list[Vuln] = []
        seen: set[str] = set()
        for rec in self.index.get((eco, name.lower()), []):
            hit, fixed = _record_matches(rec, name, version)
            if hit:
                v = _extract_vuln(rec, fixed)
                if v.id not in seen:
                    seen.add(v.id)
                    out.append(v)
        if self.online:
            out += self._query_online(ecosystem, name, version, seen)
        return out

    def _query_online(self, ecosystem: str, name: str, version: str,
                      seen: set[str]) -> list[Vuln]:
        key = (ecosystem, name.lower(), version or "")
        if key in self._online_cache:
            return [v for v in self._online_cache[key] if v.id not in seen]
        query: dict = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            query["version"] = version
        try:
            data = json.dumps(query).encode()
            req = urllib.request.Request(
                "https://api.osv.dev/v1/query", data=data,
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            self._online_cache[key] = []
            return []
        res: list[Vuln] = []
        for rec in body.get("vulns", []) or []:
            _hit, fixed = _record_matches(rec, name, version or "0")
            res.append(_extract_vuln(rec, fixed))
        self._online_cache[key] = res
        return [v for v in res if v.id not in seen]

    def enabled(self) -> bool:
        return self.online or self.loaded > 0


# --------------------------------------------------------------------------- #
# GHSA — GitHub Advisory Database (GraphQL, real-time, needs a token)
# --------------------------------------------------------------------------- #

# OSV ecosystem -> GHSA SecurityAdvisoryEcosystem enum
GHSA_ECOSYSTEM = {
    "pypi": "PIP", "npm": "NPM", "packagist": "COMPOSER", "go": "GO",
    "rubygems": "RUBYGEMS", "maven": "MAVEN", "nuget": "NUGET",
    "crates.io": "RUST", "pub": "PUB", "hex": "ERLANG", "swifturl": "SWIFT",
}

_GHSA_QUERY = (
    "query($eco:SecurityAdvisoryEcosystem!,$pkg:String!){"
    "securityVulnerabilities(ecosystem:$eco,package:$pkg,first:50){nodes{"
    "advisory{ghsaId identifiers{type value} summary severity} "
    "vulnerableVersionRange firstPatchedVersion{identifier}}}}"
)


class GhsaProvider:
    def __init__(self, token: str, timeout: int = 20):
        self.token = token
        self.timeout = timeout
        self._cache: dict[tuple[str, str], list[dict]] = {}

    def enabled(self) -> bool:
        return bool(self.token)

    def _query(self, eco_enum: str, pkg: str) -> list[dict]:
        key = (eco_enum, pkg.lower())
        if key in self._cache:
            return self._cache[key]
        body = json.dumps({"query": _GHSA_QUERY,
                           "variables": {"eco": eco_enum, "pkg": pkg}}).encode()
        req = urllib.request.Request(
            "https://api.github.com/graphql", data=body, method="POST",
            headers={"Authorization": f"bearer {self.token}",
                     "Content-Type": "application/json",
                     "User-Agent": "ai-vuln-harness"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            self._cache[key] = []
            return []
        nodes = (((data.get("data") or {}).get("securityVulnerabilities")
                  or {}).get("nodes") or [])
        self._cache[key] = nodes
        return nodes

    def vulns_for(self, ecosystem: str, name: str, version: str) -> list[Vuln]:
        eco_enum = GHSA_ECOSYSTEM.get(ecosystem.split(":")[0].lower())
        if not eco_enum or not self.enabled():
            return []
        out: list[Vuln] = []
        seen: set[str] = set()
        for node in self._query(eco_enum, name):
            rng = node.get("vulnerableVersionRange") or ""
            if version and rng and not version_in_range(version, rng):
                continue
            adv = node.get("advisory") or {}
            cve = next((i.get("value") for i in adv.get("identifiers", [])
                        if i.get("type") == "CVE"), "")
            ident = cve or adv.get("ghsaId", "")
            if not ident or ident in seen:
                continue
            seen.add(ident)
            fixed = (node.get("firstPatchedVersion") or {}).get("identifier", "")
            out.append(Vuln(id=(f"{cve} ({adv.get('ghsaId')})" if cve
                               else adv.get("ghsaId", "")),
                            summary=adv.get("summary", ""),
                            severity=(adv.get("severity") or "").upper(),
                            fixed=fixed))
        return out


# --------------------------------------------------------------------------- #
# NVD — NIST National Vulnerability Database (REST 2.0, authoritative)
# --------------------------------------------------------------------------- #

class NvdProvider:
    def __init__(self, api_key: str = "", timeout: int = 25):
        self.api_key = api_key
        self.timeout = timeout
        self._on = True
        self._cache: dict[str, list[dict]] = {}

    def enabled(self) -> bool:
        return self._on

    def _query(self, name: str) -> list[dict]:
        if name.lower() in self._cache:
            return self._cache[name.lower()]
        url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?keywordSearch={urllib.request.quote(name)}"
               "&keywordExactMatch&resultsPerPage=50")
        headers = {"User-Agent": "ai-vuln-harness"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            self._cache[name.lower()] = []
            return []
        self._cache[name.lower()] = data.get("vulnerabilities", []) or []
        return self._cache[name.lower()]

    @staticmethod
    def _cpe_hit(cve: dict, name: str, version: str) -> bool:
        nm = name.lower()
        for cfg in cve.get("configurations", []) or []:
            for node in cfg.get("nodes", []) or []:
                for cm in node.get("cpeMatch", []) or []:
                    crit = cm.get("criteria", "")
                    parts = crit.split(":")
                    product = parts[4] if len(parts) > 4 else ""
                    if product.lower() != nm:
                        continue
                    if not version:
                        return True
                    lo_i = cm.get("versionStartIncluding")
                    lo_e = cm.get("versionStartExcluding")
                    hi_i = cm.get("versionEndIncluding")
                    hi_e = cm.get("versionEndExcluding")
                    ok = True
                    if lo_i and cmp_ver(version, lo_i) < 0:
                        ok = False
                    if lo_e and cmp_ver(version, lo_e) <= 0:
                        ok = False
                    if hi_i and cmp_ver(version, hi_i) > 0:
                        ok = False
                    if hi_e and cmp_ver(version, hi_e) >= 0:
                        ok = False
                    # exact version pinned in the CPE itself
                    ver_field = parts[5] if len(parts) > 5 else "*"
                    if ver_field not in ("*", "-") and not (lo_i or lo_e or
                                                            hi_i or hi_e):
                        ok = cmp_ver(version, ver_field) == 0
                    if ok:
                        return True
        return False

    def vulns_for(self, ecosystem: str, name: str, version: str) -> list[Vuln]:
        out: list[Vuln] = []
        for item in self._query(name):
            cve = item.get("cve", {})
            if not self._cpe_hit(cve, name, version):
                continue
            cid = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []) or []:
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:160]
                    break
            sev = ""
            metrics = cve.get("metrics", {})
            for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(mk):
                    sev = (metrics[mk][0].get("cvssData", {})
                           .get("baseSeverity", "")
                           or metrics[mk][0].get("baseSeverity", ""))
                    break
            out.append(Vuln(id=cid, summary=desc, severity=sev.upper()))
        return out


# --------------------------------------------------------------------------- #
# Native audit — shell out to the ecosystem's own auditor (freshest, exact)
# --------------------------------------------------------------------------- #

class NativeAuditProvider:
    """Runs pip-audit / npm audit / composer audit / cargo audit over the repo
    and indexes results by (ecosystem, package). Best-effort: missing tools are
    skipped. Results reflect the real lockfile, so they're returned regardless
    of the queried version."""

    def __init__(self, root: str, timeout: int = 180):
        import shutil
        self.root = os.path.abspath(root)
        self.timeout = timeout
        self._shutil = shutil
        self.index: dict[tuple[str, str], list[Vuln]] = {}
        self.ran: list[str] = []
        self._run_all()

    def enabled(self) -> bool:
        return bool(self.index) or bool(self.ran)

    def _dirs_with(self, filename: str, cap: int = 6) -> list[str]:
        found = []
        for dp, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in
                       {"node_modules", "vendor", ".git", "venv", ".venv"}]
            if filename in files:
                found.append(dp)
            if len(found) >= cap:
                break
        return found

    def _run(self, cmd: list[str], cwd: str) -> str:
        import subprocess
        if not self._shutil.which(cmd[0]):
            return ""
        try:
            r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                               timeout=self.timeout)
            return r.stdout or ""
        except (subprocess.TimeoutExpired, OSError):
            return ""

    def _add(self, eco: str, name: str, v: Vuln) -> None:
        self.index.setdefault((eco.lower(), name.lower()), []).append(v)

    def _run_all(self) -> None:
        # --- PHP / composer ---
        for d in self._dirs_with("composer.lock"):
            out = self._run(["composer", "audit", "--format=json",
                             "--no-interaction"], d)
            if out:
                self.ran.append(f"composer audit @ {d}")
                self._parse_composer(out)
        # --- npm ---
        for d in self._dirs_with("package-lock.json"):
            out = self._run(["npm", "audit", "--json"], d)
            if out:
                self.ran.append(f"npm audit @ {d}")
                self._parse_npm(out)
        # --- Python / pip-audit ---
        for d in self._dirs_with("requirements.txt"):
            out = self._run(["pip-audit", "-f", "json", "-r",
                             "requirements.txt"], d)
            if out:
                self.ran.append(f"pip-audit @ {d}")
                self._parse_pip_audit(out)
        # --- Rust / cargo-audit ---
        for d in self._dirs_with("Cargo.lock"):
            out = self._run(["cargo", "audit", "--json"], d)
            if out:
                self.ran.append(f"cargo audit @ {d}")
                self._parse_cargo(out)

    def _parse_composer(self, out: str) -> None:
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return
        for pkg, advs in (data.get("advisories") or {}).items():
            for a in advs:
                self._add("packagist", pkg, Vuln(
                    id=a.get("cve") or a.get("advisoryId", ""),
                    summary=a.get("title", ""),
                    severity=(a.get("severity") or "").upper(),
                    fixed=""))

    def _parse_npm(self, out: str) -> None:
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return
        for name, info in (data.get("vulnerabilities") or {}).items():
            via = info.get("via", [])
            titles = [v.get("title") for v in via if isinstance(v, dict)]
            fix = info.get("fixAvailable")
            fixed = fix.get("version", "") if isinstance(fix, dict) else ""
            self._add("npm", name, Vuln(
                id=next((v.get("url", "").rsplit("/", 1)[-1] for v in via
                         if isinstance(v, dict) and v.get("url")), name),
                summary="; ".join(t for t in titles if t)[:160],
                severity=(info.get("severity") or "").upper(), fixed=fixed))

    def _parse_pip_audit(self, out: str) -> None:
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return
        deps = data.get("dependencies", data) if isinstance(data, dict) else data
        for dep in deps if isinstance(deps, list) else []:
            for v in dep.get("vulns", []) or []:
                fixes = v.get("fix_versions") or []
                self._add("pypi", dep.get("name", ""), Vuln(
                    id=next((x for x in v.get("aliases", []) or []
                             if x.startswith("CVE-")), v.get("id", "")),
                    summary=(v.get("description") or "")[:160],
                    severity="", fixed=fixes[0] if fixes else ""))

    def _parse_cargo(self, out: str) -> None:
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return
        for v in ((data.get("vulnerabilities") or {}).get("list") or []):
            adv = v.get("advisory", {})
            pkg = v.get("package", {})
            patched = (v.get("versions", {}) or {}).get("patched") or []
            self._add("crates.io", pkg.get("name", ""), Vuln(
                id=next((a for a in adv.get("aliases", []) or []
                         if a.startswith("CVE-")), adv.get("id", "")),
                summary=adv.get("title", ""), severity="",
                fixed=patched[0] if patched else ""))

    def vulns_for(self, ecosystem: str, name: str, version: str) -> list[Vuln]:
        return list(self.index.get(
            (ecosystem.split(":")[0].lower(), name.lower()), []))


# --------------------------------------------------------------------------- #
# Composite — query all configured sources and dedupe by CVE/GHSA id
# --------------------------------------------------------------------------- #

class CompositeVulnDB:
    def __init__(self, providers: list):
        self.providers = [p for p in providers if p is not None]

    def enabled(self) -> bool:
        return any(p.enabled() for p in self.providers)

    def load_dir(self, path: str) -> int:  # compat shim (OSV offline)
        total = 0
        for p in self.providers:
            if isinstance(p, OsvDatabase):
                total += p.load_dir(path)
        return total

    def vulns_for(self, ecosystem: str, name: str, version: str) -> list[Vuln]:
        out: list[Vuln] = []
        seen: set[str] = set()
        for p in self.providers:
            if not p.enabled():
                continue
            try:
                found = p.vulns_for(ecosystem, name, version)
            except Exception:
                found = []
            for v in found:
                key = v.id.split()[0] if v.id else v.summary[:40]
                if key and key not in seen:
                    seen.add(key)
                    out.append(v)
        return out
