#!/usr/bin/env python3
"""
context.py — build per-file "import context" for the vuln harness.

Two kinds of context are produced for the file under review:

  1. LOCAL imports  -> resolved to files inside the scan root; we extract their
     function/class signatures (not the whole file) so the model knows the
     shape of helpers the file calls.

  2. THIRD-PARTY deps -> resolved to a concrete version from the project's
     manifest (package.json / composer.json / requirements.txt / go.mod /
     Gemfile / pyproject.toml). Giving the model "lodash@4.17.4" lets it flag
     known-vulnerable versions and insecure library usage.

Dependency-free, best-effort, multi-language. It never fails the scan: on any
error it just returns less context.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Manifest parsing (third-party name -> version)
# --------------------------------------------------------------------------- #

def _safe_read(path: str, limit: int = 2_000_000) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def _parse_package_json(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    for key in ("dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies"):
        for name, ver in (data.get(key) or {}).items():
            out[name] = str(ver)
    return out


def _parse_composer_json(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    for key in ("require", "require-dev"):
        for name, ver in (data.get(key) or {}).items():
            out[name] = str(ver)
    return out


def _parse_requirements(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"([A-Za-z0-9_.\-\[\]]+)\s*([=<>!~]=?.*)?", line)
        if m:
            out[m.group(1).split("[")[0].lower()] = (m.group(2) or "").strip()
    return out


def _parse_pyproject(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    # [project] dependencies = ["flask>=2.0", ...]  and poetry tables.
    for m in re.finditer(r'"([A-Za-z0-9_.\-]+)\s*([=<>!~][^"]*)?"', text):
        out.setdefault(m.group(1).lower(), (m.group(2) or "").strip())
    for m in re.finditer(r'^([A-Za-z0-9_.\-]+)\s*=\s*"([^"]+)"', text, re.M):
        out.setdefault(m.group(1).lower(), m.group(2))
    return out


def _parse_go_mod(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in re.finditer(r"^\s*([\w./\-]+)\s+(v[\w.\-+]+)", text, re.M):
        out[m.group(1)] = m.group(2)
    return out


def _parse_gemfile_lock(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in re.finditer(r"^\s{4}([a-zA-Z0-9_\-]+)\s\(([^)]+)\)", text, re.M):
        out[m.group(1)] = m.group(2)
    return out


MANIFESTS = {
    "package.json": _parse_package_json,
    "composer.json": _parse_composer_json,
    "requirements.txt": _parse_requirements,
    "pyproject.toml": _parse_pyproject,
    "go.mod": _parse_go_mod,
    "Gemfile.lock": _parse_gemfile_lock,
}

# manifest filename -> OSV ecosystem
MANIFEST_ECOSYSTEM = {
    "package.json": "npm", "composer.json": "Packagist",
    "requirements.txt": "PyPI", "pyproject.toml": "PyPI",
    "go.mod": "Go", "Gemfile.lock": "RubyGems",
}


# --------------------------------------------------------------------------- #
# Import extraction per language
# --------------------------------------------------------------------------- #

@dataclass
class Imp:
    spec: str            # raw import target, e.g. "./utils", "flask", "App\\Db"
    relative: bool       # True if it looks like a local/relative path


IMPORT_PATTERNS = {
    "python": [
        (r"^\s*from\s+([.\w]+)\s+import\s+", "from"),
        (r"^\s*import\s+([.\w][\w., ]*)", "import"),
    ],
    "js": [
        (r"""import\s+(?:.+?\s+from\s+)?['"]([^'"]+)['"]""", "es"),
        (r"""require\(\s*['"]([^'"]+)['"]\s*\)""", "cjs"),
        (r"""export\s+.+?\s+from\s+['"]([^'"]+)['"]""", "reexport"),
    ],
    "php": [
        (r"""(?:require|require_once|include|include_once)\s*\(?\s*['"]([^'"]+)['"]""", "inc"),
        (r"^\s*use\s+([\\\w]+)", "use"),
    ],
    "go": [
        (r'^\s*(?:import\s+)?(?:[\w.]+\s+)?"([^"]+)"', "imp"),
    ],
    "java": [
        (r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;", "imp"),
    ],
    "ruby": [
        (r"""^\s*require(?:_relative)?\s+['"]([^'"]+)['"]""", "req"),
    ],
}

EXT_LANG = {
    ".py": "python", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
    ".mjs": "js", ".cjs": "js", ".vue": "js", ".php": "php", ".go": "go",
    ".java": "java", ".kt": "java", ".rb": "ruby",
}


def _is_relative(lang: str, spec: str) -> bool:
    if spec.startswith(".") or spec.startswith("/"):
        return True
    if lang == "php":
        # a require string with a slash or .php extension is a path
        return "/" in spec or spec.endswith(".php")
    if lang == "python":
        return spec.startswith(".")
    return False


def extract_imports(text: str, ext: str) -> list[Imp]:
    lang = EXT_LANG.get(ext.lower())
    if not lang:
        return []
    seen: set[str] = set()
    imps: list[Imp] = []
    for pat, _kind in IMPORT_PATTERNS.get(lang, []):
        for m in re.finditer(pat, text, re.M):
            spec = m.group(1).strip().rstrip(";").strip()
            if lang == "python" and _kind == "import":
                spec = spec.split(",")[0].split(" as ")[0].strip()
            if not spec or spec in seen:
                continue
            seen.add(spec)
            imps.append(Imp(spec=spec, relative=_is_relative(lang, spec)))
    return imps


# --------------------------------------------------------------------------- #
# Local resolution + signature extraction
# --------------------------------------------------------------------------- #

SIG_PATTERNS = {
    "python": re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+\w+"),
    "js": re.compile(r"^\s*(?:export\s+)?(?:default\s+)?"
                     r"(?:async\s+)?(?:function\*?\s+\w+|class\s+\w+|"
                     r"const\s+\w+\s*=\s*(?:async\s*)?\()"),
    "php": re.compile(r"^\s*(?:public|private|protected|static|abstract|final|\s)*"
                      r"(?:function\s+\w+|class\s+\w+|interface\s+\w+|trait\s+\w+)"),
    "go": re.compile(r"^\s*func\s+"),
    "java": re.compile(r"^\s*(?:public|private|protected).*(?:class|interface|\()"),
    "ruby": re.compile(r"^\s*(?:def|class|module)\s+\w+"),
}


def extract_signatures(text: str, lang: str, max_sigs: int) -> list[str]:
    pat = SIG_PATTERNS.get(lang)
    if not pat:
        return text.split("\n")[:max_sigs]
    sigs = [ln.strip() for ln in text.split("\n") if pat.match(ln)]
    return sigs[:max_sigs]


class ContextBuilder:
    """Builds import context. Constructed once per scan root."""

    def __init__(self, root: str, *, max_local_files: int = 10,
                 max_sigs_per_file: int = 25, char_budget: int = 6000,
                 cve_db=None):
        self.root = os.path.abspath(root)
        self.max_local_files = max_local_files
        self.max_sigs_per_file = max_sigs_per_file
        self.char_budget = char_budget
        self.cve_db = cve_db
        self.deps: dict[str, str] = {}
        self.dep_ecosystem: dict[str, str] = {}
        self._load_manifests()

    def _load_manifests(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames
                           if d not in {"node_modules", "vendor", ".git",
                                        "venv", ".venv", "__pycache__"}]
            for name in filenames:
                parser = MANIFESTS.get(name)
                if parser:
                    text = _safe_read(os.path.join(dirpath, name))
                    eco = MANIFEST_ECOSYSTEM.get(name, "")
                    for k, v in parser(text).items():
                        self.deps.setdefault(k, v)
                        if eco:
                            self.dep_ecosystem.setdefault(k, eco)

    # -- local file resolution ------------------------------------------- #

    def _resolve_local(self, from_file: str, spec: str, lang: str) -> str | None:
        base_dir = os.path.dirname(from_file)
        candidates: list[str] = []

        if lang == "python":
            # ".mod" / "..pkg.mod" relative, or "pkg.mod" absolute-ish
            dots = len(spec) - len(spec.lstrip("."))
            mod = spec.lstrip(".").replace(".", os.sep)
            anchor = base_dir
            for _ in range(max(dots - 1, 0)):
                anchor = os.path.dirname(anchor)
            roots = [anchor] if dots else [base_dir, self.root]
            for r in roots:
                candidates += [os.path.join(r, mod + ".py"),
                               os.path.join(r, mod, "__init__.py")]
        elif lang == "js":
            raw = os.path.normpath(os.path.join(base_dir, spec))
            for ext in ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
                        "/index.ts", "/index.js"):
                candidates.append(raw + ext)
        elif lang in ("php", "ruby"):
            raw = os.path.normpath(os.path.join(base_dir, spec))
            candidates += [raw, raw + ".php", raw + ".rb"]

        for c in candidates:
            if os.path.isfile(c) and os.path.abspath(c).startswith(self.root):
                return c
        return None

    # -- public API ------------------------------------------------------ #

    def build(self, from_file: str, text: str, ext: str) -> str:
        imps = extract_imports(text, ext)
        if not imps:
            return ""
        lang = EXT_LANG.get(ext.lower(), "")
        local_blocks: list[str] = []
        third_party: list[str] = []
        used_local = 0

        for imp in imps:
            # Always try to resolve locally first (a bare `import helpers`
            # in a flat layout is still a local file), bounded by the budget.
            resolved = None
            if used_local < self.max_local_files:
                resolved = self._resolve_local(from_file, imp.spec, lang)
            if resolved:
                used_local += 1
                snippet = _safe_read(resolved, 200_000)
                sigs = extract_signatures(snippet, lang, self.max_sigs_per_file)
                rel = os.path.relpath(resolved, self.root).replace("\\", "/")
                body = "\n".join("  " + s for s in sigs) or "  (no signatures found)"
                local_blocks.append(f"# {imp.spec}  ->  {rel}\n{body}")
            else:
                # third-party: attach a resolved version + known CVEs if any
                name, ver = self._lookup_dep(imp.spec)
                line = imp.spec + (f" @ {ver}" if ver else "")
                if name and ver and self.cve_db is not None:
                    eco = self.dep_ecosystem.get(name, "")
                    vulns = self.cve_db.vulns_for(eco, name, ver) if eco else []
                    if vulns:
                        ids = "; ".join(v.short() for v in vulns[:5])
                        line += f"\n      [KNOWN VULNS] {ids}"
                third_party.append(line)

        parts: list[str] = []
        if third_party:
            uniq = list(dict.fromkeys(third_party))
            parts.append("THIRD-PARTY DEPENDENCIES IMPORTED BY THIS FILE "
                         "(name and resolved version from project manifest -- "
                         "flag versions with known CVEs and insecure usage):\n  "
                         + "\n  ".join(uniq))
        if local_blocks:
            parts.append("LOCAL MODULES IMPORTED BY THIS FILE "
                         "(signatures only, for cross-file taint reasoning):\n"
                         + "\n\n".join(local_blocks))

        ctx = "\n\n".join(parts)
        if len(ctx) > self.char_budget:
            ctx = ctx[: self.char_budget] + "\n  ...(context truncated)"
        return ctx

    # Common import-name -> package-name mismatches.
    IMPORT_ALIAS = {
        "yaml": "pyyaml", "cv2": "opencv-python", "bs4": "beautifulsoup4",
        "pil": "pillow", "sklearn": "scikit-learn", "dotenv": "python-dotenv",
        "jwt": "pyjwt", "serial": "pyserial", "attr": "attrs",
    }

    def _lookup_dep(self, spec: str) -> tuple[str | None, str]:
        """Return (canonical manifest name, clean version) for an import spec."""
        top = spec.split(".")[0].split("/")[-1].split("\\")[-1]
        for key in (spec, spec.split("/")[-1], spec.split("\\")[-1],
                    spec.lower(), top.lower(),
                    self.IMPORT_ALIAS.get(top.lower(), "")):
            if key and key in self.deps:
                return key, self.deps[key].lstrip("=<>!~^ ~").strip()
        return None, ""

    def dep_vulns(self) -> list[dict]:
        """Every manifest dependency with a known CVE (project-wide, deduped).

        Returns dicts: {name, version, ecosystem, vulns:[Vuln]}.
        """
        if self.cve_db is None or not self.cve_db.enabled():
            return []
        out: list[dict] = []
        for name, raw_ver in self.deps.items():
            ver = raw_ver.lstrip("=<>!~^ ~").strip()
            eco = self.dep_ecosystem.get(name, "")
            if not ver or not eco:
                continue
            vulns = self.cve_db.vulns_for(eco, name, ver)
            if vulns:
                out.append({"name": name, "version": ver,
                            "ecosystem": eco, "vulns": vulns})
        return out
