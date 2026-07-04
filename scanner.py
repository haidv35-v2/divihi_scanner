#!/usr/bin/env python3
"""
ai-vuln-harness
===============
A file-by-file source code vulnerability review harness driven by a LOCAL AI model.

Inspired by projectblack.io "Local AI for Cyber Security". Core idea:
  For each source file:  model reviews ONE file (+ line numbers) -> structured findings
  All findings are streamed to an NDJSON report (one JSON finding per line).

Providers
---------
  * ollama  : native Ollama /api/chat  (default: http://localhost:11434)
  * openai  : any OpenAI-compatible /v1/chat/completions endpoint
              (LM Studio, vLLM, llama.cpp server, OpenRouter, custom gateway, ...)

No third-party dependencies -- uses only the Python standard library.

Finding schema (each NDJSON line)
---------------------------------
  severity        Critical | High | Medium | Low | Info
  description     What the vulnerability is
  affected_code   File + line range + the offending snippet
  attack_path     How an attacker reaches and exploits it
  evidence        Concrete reasons this is exploitable (tainted source -> sink)
  confidence      High | Medium | Low
  recommendation  How to fix it
  (plus harness metadata: file, lines, cwe, model, timestamp, id)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    from context import ContextBuilder
except ImportError:  # allow running from another cwd
    ContextBuilder = None  # type: ignore
try:
    from cve import OsvDatabase
except ImportError:
    OsvDatabase = None  # type: ignore
try:
    import chain as chainmod
except ImportError:
    chainmod = None  # type: ignore
try:
    from skills import SkillSet
except ImportError:
    SkillSet = None  # type: ignore

# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #

DEFAULT_EXTS = [
    ".php", ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".java",
    ".c", ".cc", ".cpp", ".cs", ".rs", ".sh", ".pl", ".ps1", ".sql",
    ".html", ".htm", ".vue", ".aspx", ".jsp", ".kt", ".scala", ".lua",
]

# Directories we never want to walk into.
SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "venv", ".venv",
    "__pycache__", "dist", "build", ".next", ".nuxt", "target",
    "bower_components", ".idea", ".vscode", "site-packages",
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# JSON schema used both to guide the model and to validate output.
FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["Critical", "High", "Medium", "Low", "Info"],
                    },
                    "description": {"type": "string"},
                    "affected_code": {"type": "string"},
                    "start_line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                    "attack_path": {"type": "string"},
                    "evidence": {"type": "string"},
                    "confidence": {
                        "type": "string",
                        "enum": ["High", "Medium", "Low"],
                    },
                    "recommendation": {"type": "string"},
                    "cwe": {"type": "string"},
                },
                "required": [
                    "severity", "description", "affected_code",
                    "attack_path", "evidence", "confidence", "recommendation",
                ],
            },
        }
    },
    "required": ["findings"],
}

SYSTEM_PROMPT = """\
You are a senior application security auditor performing a manual source code \
review. You are reviewing ONE file at a time. Your job is to find real, \
exploitable security vulnerabilities -- not style issues.

Focus on high-signal sink/source vulnerability classes:
  - Command injection (exec, system, popen, shell_exec, subprocess with shell=True)
  - Code injection / eval / deserialization of untrusted data
  - Local/Remote File Inclusion (require/include/require_once with user input)
  - Path traversal / arbitrary file read or write
  - SQL / NoSQL injection (string-built queries)
  - Server-Side Template Injection, SSRF, XXE
  - Authentication / authorization / access-control flaws
  - Hardcoded secrets, insecure crypto, insecure randomness
  - XSS (reflected/stored), open redirect, CSRF where relevant
  - Use of a third-party dependency version with known CVEs, or dangerous/
    deprecated APIs of an imported library (a CONTEXT section may list the
    imported packages with their resolved versions)

Rules:
  - Only report issues where you can trace UNTRUSTED INPUT reaching a DANGEROUS SINK,
    OR a concrete security weakness (hardcoded secret, broken auth check).
  - Prefer precision over recall. If you are guessing, set confidence "Low".
  - Cite exact line numbers shown in the file (the format is `<lineno>| code`).
  - Do NOT invent code that is not in the file.
  - If the file has no security-relevant issues, return an empty findings array.

Output ONLY a single JSON object, no prose, no markdown, no code fences. Use
exactly this shape (the findings array may be empty):
{"findings": [
  {"severity": "Critical|High|Medium|Low|Info",
   "description": "...", "affected_code": "<code with line numbers>",
   "start_line": 0, "end_line": 0, "attack_path": "...", "evidence": "...",
   "confidence": "High|Medium|Low", "recommendation": "...", "cwe": "CWE-..."}
]}"""

USER_PROMPT_TEMPLATE = """\
Review this file for security vulnerabilities.

FILE: {path}
LANGUAGE: {lang}
LINES: {start}-{end}{trunc_note}
{context_block}
Each line is prefixed with `<lineno>| `. Use those numbers when citing code.

--- BEGIN FILE ---
{body}
--- END FILE ---

For every vulnerability, provide:
  severity, description, affected_code (the exact offending snippet with line
  numbers), start_line, end_line, attack_path, evidence, confidence,
  recommendation, and cwe if known.

Return JSON only."""

CHAIN_SYSTEM = """\
You are an expert in insecure deserialization and gadget-chain exploitation \
(PHP POP chains, Java/.NET gadget chains, Python pickle chains, Ruby Marshal).

You are given ONE deserialization SINK (where untrusted data is deserialized) \
and a set of CANDIDATE GADGET CLASSES from the SAME codebase (classes exposing \
magic/callback methods a chain can pivot through), plus any known-vulnerable \
deserialization libraries present.

Your task: determine whether an attacker who controls the serialized input can \
build an exploitable object-injection / gadget chain that reaches a dangerous \
effect (RCE, file write/read, SSRF, SQLi, arbitrary method call).

Rules:
  - Trace a CONCRETE chain: entry (which magic method fires first on \
    deserialization) -> intermediate pivots -> final dangerous sink. Name the \
    exact classes and methods and the files they live in.
  - Only report a chain you can actually assemble from the classes shown (or a \
    named known-vulnerable library). If the pieces are missing, say so and set \
    confidence "Low" or return no findings.
  - The `attack_path` MUST list the chain step by step.
  - The `evidence` MUST cite the class::method and line for each hop.
  - Do NOT invent methods that are not in the provided code.

Output ONLY a single JSON object, no prose, no markdown, no code fences:
{"findings": [
  {"severity": "Critical|High|Medium|Low|Info",
   "description": "insecure deserialization -> <gadget chain summary>",
   "affected_code": "<sink line + key gadget lines with file:line>",
   "start_line": 0, "end_line": 0,
   "attack_path": "step 1 ... -> step 2 ... -> RCE",
   "evidence": "ClassA::__wakeup (fileA:12) -> ClassB::__toString (fileB:30) -> ...",
   "confidence": "High|Medium|Low",
   "recommendation": "...", "cwe": "CWE-502"}
]}"""

CHAIN_USER = """\
Deserialization sink language: {lang}
Sink location: {sink_file}:{sink_line}

Analyze the following sink and candidate gadget classes. Build the most \
plausible exploitable chain, or report none if the gadgets are insufficient.

{context}

Return the JSON object only."""

VERIFY_SCHEMA = {
    "type": "object",
    "properties": {
        "is_real": {"type": "boolean"},
        "verdict": {"type": "string",
                    "enum": ["true_positive", "false_positive", "uncertain"]},
        "adjusted_severity": {
            "type": "string",
            "enum": ["Critical", "High", "Medium", "Low", "Info"]},
        "adjusted_confidence": {
            "type": "string", "enum": ["High", "Medium", "Low"]},
        "reasoning": {"type": "string"},
    },
    "required": ["is_real", "verdict", "adjusted_confidence", "reasoning"],
}

VERIFY_SYSTEM = """\
You are a skeptical secondary reviewer auditing another analyst's vulnerability \
finding. Your job is to REFUTE it. Assume it is a false positive until the code \
proves otherwise.

A finding is a TRUE positive ONLY if, in the code shown, untrusted/attacker-\
controlled input actually reaches the dangerous sink WITHOUT an effective \
sanitizer/validator/guard in between, OR it is a concrete standalone weakness \
(real hardcoded secret, genuinely vulnerable dependency version, broken auth \
check that actually gates something).

Mark it a FALSE positive if: the input is a constant/trusted, it is sanitized \
or parameterized, the sink is not actually dangerous as used, the "secret" is a \
placeholder/example, the code path is unreachable, or the claim is not supported \
by the code shown. If you cannot tell from the code provided, use "uncertain" \
and confidence "Low".

Output ONLY a single JSON object, no prose, no markdown, no code fences. Use
exactly this shape:
{"is_real": true, "verdict": "true_positive|false_positive|uncertain",
 "adjusted_severity": "Critical|High|Medium|Low|Info",
 "adjusted_confidence": "High|Medium|Low", "reasoning": "..."}"""

VERIFY_USER = """\
Original finding to judge:
  severity:       {severity}
  description:    {description}
  attack_path:    {attack_path}
  evidence:       {evidence}
  affected_code:  {affected_code}

Here is the actual code (line-numbered) around the reported location{ctx_note}:

--- BEGIN CODE ---
{code}
--- END CODE ---

Decide: is this a real, exploitable vulnerability given ONLY this code? Provide
is_real, verdict, adjusted_severity, adjusted_confidence, and reasoning."""

_print_lock = threading.Lock()
_write_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# Data
# --------------------------------------------------------------------------- #

@dataclass
class Config:
    path: str
    out: str
    provider: str = "ollama"
    model: str = "qwen3:30b"
    base_url: str = ""
    api_key: str = ""
    extra_headers: dict = field(default_factory=dict)
    structured: str = "schema"   # schema | json_object | off
    exts: list[str] = field(default_factory=lambda: list(DEFAULT_EXTS))
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    num_ctx: int = 16384
    temperature: float = 0.1
    max_file_bytes: int = 400_000
    chunk_lines: int = 700
    chunk_overlap: int = 40
    workers: int = 1
    timeout: int = 600
    retries: int = 2
    min_confidence: str = "Low"
    verbose: bool = False
    with_imports: bool = True
    context_budget: int = 6000
    max_local_imports: int = 10
    verify: bool = False
    keep_fp: bool = False
    osv_db: str = ""
    osv_online: bool = False
    ghsa: bool = False
    github_token: str = ""
    nvd: bool = False
    nvd_api_key: str = ""
    native_audit: bool = False
    mode: str = "file"          # file | chain
    chain_budget: int = 60000
    max_chains: int = 20
    skills: list[str] = field(default_factory=list)
    skill_budget: int = 80000
    price_in: float = -1.0      # USD per 1M input tokens (-1 = auto/unset)
    price_out: float = -1.0     # USD per 1M output tokens


def log(msg: str, *, err: bool = True) -> None:
    with _print_lock:
        print(msg, file=sys.stderr if err else sys.stdout, flush=True)


# --------------------------------------------------------------------------- #
# .env support  (no third-party deps)
# --------------------------------------------------------------------------- #

def load_dotenv(path: str = ".env") -> int:
    """Load KEY=VALUE pairs from a .env file into os.environ.

    Existing environment variables are NOT overwritten (real env wins over
    the file). Supports `export KEY=v`, quotes, `#` comments, blank lines.
    Returns the number of keys loaded.
    """
    if not os.path.isfile(path):
        return 0
    n = 0
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
                    n += 1
    except OSError:
        return 0
    return n


def _env(key: str, default):
    return os.environ.get(key, default)


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ[key])
    except (KeyError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ[key])
    except (KeyError, ValueError):
        return default


# --------------------------------------------------------------------------- #
# LLM providers
# --------------------------------------------------------------------------- #

class LLMError(RuntimeError):
    pass


# Cloudflare-fronted gateways commonly 403 the default "Python-urllib" UA.
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/125.0 Safari/537.36")


def _http_post(url: str, payload: dict, headers: dict, timeout: int) -> dict:
    data = json.dumps(payload).encode("utf-8")
    headers = {"User-Agent": DEFAULT_UA, "Accept": "application/json", **headers}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise LLMError(f"HTTP {e.code} from {url}: {body[:500]}") from e
    except urllib.error.URLError as e:
        raise LLMError(f"Cannot reach {url}: {e.reason}") from e
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise LLMError(f"Non-JSON transport response: {raw[:500]}") from e


def call_ollama(cfg: Config, system: str, user: str, schema: dict) -> str:
    """Native Ollama chat API with JSON-schema constrained output."""
    base = cfg.base_url or "http://localhost:11434"
    url = base.rstrip("/") + "/api/chat"
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "format": schema,                  # structured output constraint
        "options": {
            "temperature": cfg.temperature,
            "num_ctx": cfg.num_ctx,
        },
    }
    headers = {"Content-Type": "application/json"}
    headers.update(cfg.extra_headers)   # e.g. auth for a proxied Ollama
    resp = _http_post(url, payload, headers, cfg.timeout)
    usage = {"input": resp.get("prompt_eval_count", 0),
             "output": resp.get("eval_count", 0)}
    return resp.get("message", {}).get("content", ""), usage


def call_openai(cfg: Config, system: str, user: str, schema: dict) -> str:
    """OpenAI-compatible /v1/chat/completions (LM Studio, vLLM, llama.cpp, ...)."""
    base = cfg.base_url or "http://localhost:11434/v1"
    url = base.rstrip("/") + "/chat/completions"
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": cfg.temperature,
        "stream": False,
    }
    # Structured-output mode. Anthropic/Claude proxies reject "json_schema"
    # (they use tool-use instead) -> set --structured json_object (or off).
    if cfg.structured == "schema":
        payload["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "structured_output", "strict": True,
                            "schema": schema},
        }
    elif cfg.structured == "json_object":
        payload["response_format"] = {"type": "json_object"}
    # "off": no response_format; rely on the prompt + extract_json parser.

    headers = {"Content-Type": "application/json"}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    headers.update(cfg.extra_headers)   # custom/override headers win
    try:
        resp = _http_post(url, payload, headers, cfg.timeout)
    except LLMError:
        # Server rejected the structured hint: degrade json_schema -> json_object
        # -> none, and retry once so one picky endpoint doesn't kill the scan.
        if cfg.structured == "schema":
            payload["response_format"] = {"type": "json_object"}
        else:
            payload.pop("response_format", None)
        resp = _http_post(url, payload, headers, cfg.timeout)
    u = resp.get("usage", {}) or {}
    usage = {"input": u.get("prompt_tokens", 0),
             "output": u.get("completion_tokens", 0)}
    return resp["choices"][0]["message"]["content"], usage


def call_model(cfg: Config, system: str, user: str,
               schema: dict = FINDING_SCHEMA) -> tuple[str, dict]:
    """Return (content, usage). usage = {'input': int, 'output': int} (may be
    zeros if the endpoint doesn't report token counts)."""
    if cfg.provider == "ollama":
        return call_ollama(cfg, system, user, schema)
    if cfg.provider in ("openai", "custom"):
        return call_openai(cfg, system, user, schema)
    raise LLMError(f"Unknown provider: {cfg.provider}")


# --------------------------------------------------------------------------- #
# Parsing model output
# --------------------------------------------------------------------------- #

def extract_json(text: str) -> dict:
    """Best-effort extraction of a JSON object from model output."""
    text = text.strip()
    if not text:
        return {"findings": []}
    # Strip ```json ... ``` fences if the model added them anyway.
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Fall back to the widest {...} or [...] span.
    for open_c, close_c in (("{", "}"), ("[", "]")):
        start = text.find(open_c)
        end = text.rfind(close_c)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                continue
    raise LLMError(f"Could not parse model JSON: {text[:300]}")


def normalize_findings(raw) -> list[dict]:
    # Accept several shapes models emit when a strict schema isn't enforced:
    #   {"findings": [...]}   • bare list [...]   • single finding {...}
    #   {"vulnerabilities": [...]} / {"results": [...]}
    if isinstance(raw, list):
        findings = raw
    elif isinstance(raw, dict):
        findings = None
        for key in ("findings", "vulnerabilities", "results", "issues"):
            if isinstance(raw.get(key), list):
                findings = raw[key]
                break
        if findings is None:
            findings = [raw] if "severity" in raw or "description" in raw else []
    else:
        return []
    if not isinstance(findings, list):
        return []
    clean: list[dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity", "Info")).capitalize()
        if sev not in SEVERITY_ORDER:
            sev = "Info"
        conf = str(f.get("confidence", "Low")).capitalize()
        if conf not in ("High", "Medium", "Low"):
            conf = "Low"
        clean.append({
            "severity": sev,
            "description": str(f.get("description", "")).strip(),
            "affected_code": str(f.get("affected_code", "")).strip(),
            "start_line": f.get("start_line"),
            "end_line": f.get("end_line"),
            "attack_path": str(f.get("attack_path", "")).strip(),
            "evidence": str(f.get("evidence", "")).strip(),
            "confidence": conf,
            "recommendation": str(f.get("recommendation", "")).strip(),
            "cwe": str(f.get("cwe", "")).strip(),
        })
    return clean


# --------------------------------------------------------------------------- #
# File handling
# --------------------------------------------------------------------------- #

LANG_BY_EXT = {
    ".php": "PHP", ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".jsx": "JavaScript/React", ".tsx": "TypeScript/React", ".rb": "Ruby",
    ".go": "Go", ".java": "Java", ".c": "C", ".cc": "C++", ".cpp": "C++",
    ".cs": "C#", ".rs": "Rust", ".sh": "Shell", ".pl": "Perl",
    ".ps1": "PowerShell", ".sql": "SQL", ".html": "HTML", ".vue": "Vue",
    ".aspx": "ASP.NET", ".jsp": "JSP", ".kt": "Kotlin", ".lua": "Lua",
}


def looks_binary(sample: bytes) -> bool:
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    text_chars = bytes(range(32, 127)) + b"\n\r\t\f\b"
    nontext = sum(1 for b in sample if b not in text_chars)
    return nontext / len(sample) > 0.30


def should_scan(rel: str, name: str, cfg: Config) -> bool:
    ext = os.path.splitext(name)[1].lower()
    if cfg.exts and ext not in cfg.exts:
        return False
    if cfg.include and not any(fnmatch.fnmatch(rel, g) for g in cfg.include):
        return False
    if cfg.exclude and any(fnmatch.fnmatch(rel, g) for g in cfg.exclude):
        return False
    return True


def discover_files(cfg: Config) -> list[str]:
    root = os.path.abspath(cfg.path)
    if os.path.isfile(root):
        return [root]
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if should_scan(rel.replace("\\", "/"), name, cfg):
                out.append(full)
    out.sort()
    return out


def read_text(path: str, cfg: Config) -> str | None:
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size == 0 or size > cfg.max_file_bytes:
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if looks_binary(data[:2048]):
        return None
    return data.decode("utf-8", "replace")


def number_lines(text: str, start: int) -> str:
    lines = text.split("\n")
    return "\n".join(f"{start + i}| {ln}" for i, ln in enumerate(lines))


def chunk_file(text: str, cfg: Config) -> list[tuple[int, int, str]]:
    """Split into (start_line, end_line, body) tuples with line numbers.

    Small files -> a single chunk. Large files -> overlapping windows so a
    vulnerability straddling a boundary is still seen whole once.
    """
    lines = text.split("\n")
    total = len(lines)
    if total <= cfg.chunk_lines:
        return [(1, total, number_lines(text, 1))]
    chunks: list[tuple[int, int, str]] = []
    step = cfg.chunk_lines - cfg.chunk_overlap
    i = 0
    while i < total:
        seg = lines[i:i + cfg.chunk_lines]
        body = "\n".join(f"{i + 1 + j}| {ln}" for j, ln in enumerate(seg))
        chunks.append((i + 1, i + len(seg), body))
        i += step
    return chunks


# --------------------------------------------------------------------------- #
# Scan orchestration
# --------------------------------------------------------------------------- #

@dataclass
class Stats:
    files_scanned: int = 0
    files_skipped: int = 0
    files_errored: int = 0
    findings: int = 0
    by_severity: dict = field(default_factory=lambda: {k: 0 for k in SEVERITY_ORDER})
    prompt_tokens: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0
    usage_estimated: bool = False
    verified: int = 0
    false_positives: int = 0
    dep_findings: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def account(self, usage: dict, prompt: str, output: str) -> None:
        """Record token usage from one model call (real if reported, else est.)."""
        with self.lock:
            self.calls += 1
            if usage and (usage.get("input") or usage.get("output")):
                self.input_tokens += usage.get("input", 0)
                self.output_tokens += usage.get("output", 0)
            else:
                self.input_tokens += max(1, len(prompt) // 4)
                self.output_tokens += max(1, len(output) // 4)
                self.usage_estimated = True


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def code_window(text: str, start: int | None, end: int | None,
                margin: int = 25) -> str:
    """Numbered code window around [start,end] (1-based), for the verify pass."""
    lines = text.split("\n")
    if not start:
        seg = lines[: 2 * margin]
        return "\n".join(f"{i + 1}| {ln}" for i, ln in enumerate(seg))
    lo = max(1, start - margin)
    hi = min(len(lines), (end or start) + margin)
    return "\n".join(f"{i}| {lines[i - 1]}" for i in range(lo, hi + 1))


def _parse_verdict_text(raw: str) -> dict | None:
    """Fallback: pull a verdict out of markdown/prose like `**is_real:** true`."""
    import re
    low = raw.lower()

    def grab(key: str) -> str:
        m = re.search(rf"{key}\W{{0,4}}\s*([^\n*]+)", low)
        return m.group(1).strip(" *:").strip() if m else ""

    if "is_real" not in low and "false_positive" not in low \
            and "true_positive" not in low:
        return None
    is_real_s = grab("is_real")
    verdict = grab("verdict")
    is_real = ("true" in is_real_s if is_real_s
               else ("false_positive" not in verdict and "false" not in verdict))
    sev = grab("adjusted_severity").capitalize()
    conf = grab("adjusted_confidence").capitalize()
    return {
        "is_real": is_real,
        "verdict": ("false_positive" if not is_real else
                    ("true_positive" if "true" in verdict or is_real
                     else "uncertain")),
        "adjusted_severity": sev if sev in SEVERITY_ORDER else None,
        "adjusted_confidence": conf if conf in ("High", "Medium", "Low") else None,
        "reasoning": (raw.split("reasoning", 1)[-1].lstrip(" *:></-\n")[:600]
                      if "reasoning" in low else raw[:300]),
    }


def verify_finding(cfg: Config, text: str, finding: dict,
                   stats: "Stats | None" = None) -> dict | None:
    """Second-pass adversarial check. Returns a verdict dict or None on error."""
    code = code_window(text, finding.get("start_line"), finding.get("end_line"))
    user = VERIFY_USER.format(
        severity=finding["severity"], description=finding["description"],
        attack_path=finding["attack_path"], evidence=finding["evidence"],
        affected_code=finding["affected_code"][:600],
        ctx_note=" (a window around it)" if finding.get("start_line") else "",
        code=code[:12000],
    )
    for attempt in range(cfg.retries + 1):
        try:
            raw, usage = call_model(cfg, VERIFY_SYSTEM, user, VERIFY_SCHEMA)
            if stats is not None:
                stats.account(usage, VERIFY_SYSTEM + user, raw)
        except LLMError:
            if attempt >= cfg.retries:
                return None
            time.sleep(1.0 * (attempt + 1))
            continue
        # Try JSON first, then fall back to markdown/prose verdicts.
        try:
            data = extract_json(raw)
            if isinstance(data, dict) and "is_real" in data:
                return data
        except LLMError:
            pass
        kv = _parse_verdict_text(raw)
        if kv is not None:
            return kv
    return None


def scan_one_file(cfg: Config, root: str, path: str, stats: Stats,
                  out_fh, ctx_builder=None, skillset=None) -> None:
    rel = os.path.relpath(path, root).replace("\\", "/")
    text = read_text(path, cfg)
    if text is None:
        with stats.lock:
            stats.files_skipped += 1
        if cfg.verbose:
            log(f"  skip  {rel}")
        return

    ext = os.path.splitext(path)[1].lower()
    lang = LANG_BY_EXT.get(ext, ext.lstrip(".") or "text")

    # Inject external skill / knowledge-pack guidance into the reviewer prompt.
    system_prompt = SYSTEM_PROMPT
    if skillset is not None:
        guidance = skillset.guidance_for(ext)
        if guidance:
            system_prompt = SYSTEM_PROMPT + "\n\n" + guidance

    context_block = ""
    if ctx_builder is not None:
        try:
            ctx = ctx_builder.build(path, text, ext)
        except Exception as e:  # never let context break the scan
            ctx = ""
            if cfg.verbose:
                log(f"  ctx-fail {rel}: {e}")
        if ctx:
            context_block = "\n--- IMPORT CONTEXT ---\n" + ctx + "\n"

    chunks = chunk_file(text, cfg)
    file_findings: list[dict] = []

    for (start, end, body) in chunks:
        trunc = "" if len(chunks) == 1 else f" (chunk {start}-{end} of file)"
        user = USER_PROMPT_TEMPLATE.format(
            path=rel, lang=lang, start=start, end=end,
            trunc_note=trunc, body=body, context_block=context_block,
        )

        content = ""
        for attempt in range(cfg.retries + 1):
            try:
                content, usage = call_model(cfg, system_prompt, user)
                stats.account(usage, system_prompt + user, content)
                break
            except LLMError as e:
                if attempt >= cfg.retries:
                    with stats.lock:
                        stats.files_errored += 1
                    log(f"  ERROR {rel} [{start}-{end}]: {e}")
                    content = ""
                else:
                    time.sleep(1.5 * (attempt + 1))
        if not content:
            continue

        try:
            findings = normalize_findings(extract_json(content))
        except LLMError as e:
            log(f"  parse-fail {rel} [{start}-{end}]: {e}")
            continue

        for f in findings:
            if SEVERITY_ORDER.get(f["confidence"]) is None:
                pass
            file_findings.append(f)

    # Drop below the confidence floor.
    conf_rank = {"High": 0, "Medium": 1, "Low": 2}
    floor = conf_rank.get(cfg.min_confidence, 2)
    kept = [f for f in file_findings if conf_rank.get(f["confidence"], 2) <= floor]

    # ----- second pass: adversarial verification -----
    dropped_fp = 0
    if cfg.verify and kept:
        surviving: list[dict] = []
        for f in kept:
            verdict = verify_finding(cfg, text, f, stats)
            with stats.lock:
                stats.verified += 1
            if verdict is None:
                f["verify"] = {"verdict": "unchecked", "reasoning": "verify failed"}
                surviving.append(f)
                continue
            is_real = bool(verdict.get("is_real"))
            f["verify"] = {
                "verdict": verdict.get("verdict", ""),
                "is_real": is_real,
                "reasoning": verdict.get("reasoning", ""),
            }
            if verdict.get("adjusted_severity") in SEVERITY_ORDER:
                f["severity"] = verdict["adjusted_severity"]
            if verdict.get("adjusted_confidence") in conf_rank:
                f["confidence"] = verdict["adjusted_confidence"]
            if not is_real and not cfg.keep_fp:
                dropped_fp += 1
                with stats.lock:
                    stats.false_positives += 1
                continue
            surviving.append(f)
        kept = surviving

    with _write_lock:
        for f in kept:
            record = {
                "id": hashlib.sha1(
                    f"{rel}:{f.get('start_line')}:{f['description'][:80]}"
                    .encode()).hexdigest()[:12],
                "type": "code",
                "file": rel,
                "lines": f"{f.get('start_line')}-{f.get('end_line')}"
                         if f.get("start_line") else None,
                "severity": f["severity"],
                "description": f["description"],
                "affected_code": f["affected_code"],
                "attack_path": f["attack_path"],
                "evidence": f["evidence"],
                "confidence": f["confidence"],
                "recommendation": f["recommendation"],
                "cwe": f["cwe"],
                "verify": f.get("verify"),
                "model": cfg.model,
                "provider": cfg.provider,
                "timestamp": now_iso(),
            }
            out_fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        out_fh.flush()

    with stats.lock:
        stats.files_scanned += 1
        stats.findings += len(kept)
        for f in kept:
            stats.by_severity[f["severity"]] += 1

    if kept:
        top = min(kept, key=lambda x: SEVERITY_ORDER[x["severity"]])
        fp_note = f"  (-{dropped_fp} FP)" if dropped_fp else ""
        log(f"  [{len(kept):>2}] {rel}  (top: {top['severity']}){fp_note}")
    elif cfg.verbose or dropped_fp:
        log(f"  [ 0] {rel}" + (f"  (-{dropped_fp} FP)" if dropped_fp else ""))


def _write_finding_record(out_fh, rel: str, f: dict, cfg: Config,
                          ftype: str) -> None:
    record = {
        "id": hashlib.sha1(
            f"{ftype}:{rel}:{f.get('start_line')}:{f['description'][:80]}"
            .encode()).hexdigest()[:12],
        "type": ftype,
        "file": rel,
        "lines": f"{f.get('start_line')}-{f.get('end_line')}"
                 if f.get("start_line") else None,
        "severity": f["severity"],
        "description": f["description"],
        "affected_code": f["affected_code"],
        "attack_path": f["attack_path"],
        "evidence": f["evidence"],
        "confidence": f["confidence"],
        "recommendation": f["recommendation"],
        "cwe": f["cwe"],
        "verify": f.get("verify"),
        "model": cfg.model,
        "provider": cfg.provider,
        "timestamp": now_iso(),
    }
    out_fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def parse_chain_response(raw: str, sink) -> list[dict]:
    """Parse a chain model reply into findings, tolerating shape drift.

    Accepts {"findings":[...]}, a bare list, or a self-invented
    {"chain_found":bool, "chain":[steps]} / {"gadget_chain":[...]} object.
    """
    try:
        obj = extract_json(raw)
    except LLMError:
        return []
    # Ideal / generic shapes handled by normalize_findings.
    direct = normalize_findings(obj)
    if direct:
        return direct
    if not isinstance(obj, dict):
        return []
    steps = None
    for key in ("chain", "gadget_chain", "steps", "pop_chain"):
        if isinstance(obj.get(key), list) and obj[key]:
            steps = obj[key]
            break
    # explicit "no chain" signal
    if obj.get("chain_found") is False or obj.get("vulnerable") is False:
        return []
    if not steps:
        return []

    def hop(s: dict) -> str:
        cls = s.get("class", "?"); meth = s.get("method", "?")
        loc = s.get("file", ""); ln = s.get("line", "")
        locs = f" ({loc}:{ln})" if loc else ""
        return f"{cls}::{meth}{locs}"

    attack_path = " -> ".join(hop(s) for s in steps if isinstance(s, dict))
    evidence = "; ".join(
        f"{hop(s)}: {s.get('description', '')}"[:200]
        for s in steps if isinstance(s, dict))
    summary = (obj.get("summary") or obj.get("description")
               or f"deserialization POP/gadget chain via {attack_path}")
    return [{
        "severity": (obj.get("severity") or "Critical").capitalize(),
        "description": f"Insecure deserialization gadget chain: {summary}",
        "affected_code": f"{sink.file}:{sink.line}  {sink.snippet}",
        "attack_path": attack_path,
        "evidence": evidence,
        "confidence": "Medium",
        "recommendation": obj.get("recommendation")
        or "Do not deserialize untrusted input; use a safe format (JSON) with a "
           "strict allowlist, or signed/authenticated payloads.",
        "cwe": "CWE-502",
        "start_line": sink.line, "end_line": sink.line,
    }]


def run_chain(cfg: Config, root: str, files: list[str], stats: Stats,
              out_fh, ctx_builder, cve_db, skillset=None) -> None:
    """Whole-program gadget / deserialization chain analysis."""
    if chainmod is None:
        log("error: chain.py not importable; cannot run --mode chain")
        return

    # Read all candidate files once.
    file_texts: dict[str, str] = {}
    for p in files:
        t = read_text(p, cfg)
        if t is not None:
            file_texts[os.path.relpath(p, root).replace("\\", "/")] = t
        else:
            with stats.lock:
                stats.files_skipped += 1

    sinks, gadgets = chainmod.scan_sinks_and_gadgets(file_texts)
    n_gadget = sum(len(v) for v in gadgets.values())
    log(f"Chain mode: {len(sinks)} deserialization sink(s), "
        f"{n_gadget} gadget-candidate file(s) across "
        f"{len(gadgets)} language(s)")
    if not sinks:
        log("  no deserialization sinks found -- nothing to chain")
        return

    # Known-vulnerable deser libraries (from OSV) as extra gadget context.
    dep_note = ""
    if ctx_builder is not None and cve_db is not None:
        vulns = ctx_builder.dep_vulns()
        if vulns:
            dep_note = "\n".join(
                f"  {v['name']} {v['version']}: "
                + "; ".join(x.id for x in v["vulns"][:3]) for v in vulns[:10])

    sinks = sinks[: cfg.max_chains]
    if len(sinks) == cfg.max_chains:
        log(f"  (capped at --max-chains={cfg.max_chains} sinks)")

    for sink in sinks:
        lang_gadgets = gadgets.get(sink.lang, [])
        context = chainmod.build_chain_context(
            sink, lang_gadgets, file_texts,
            budget=cfg.chain_budget, dep_note=dep_note)
        user = CHAIN_USER.format(lang=sink.lang, sink_file=sink.file,
                                 sink_line=sink.line, context=context)

        chain_system = CHAIN_SYSTEM
        if skillset is not None:
            g = skillset.guidance_for(os.path.splitext(sink.file)[1].lower())
            if g:
                chain_system = CHAIN_SYSTEM + "\n\n" + g

        content = ""
        for attempt in range(cfg.retries + 1):
            try:
                content, usage = call_model(cfg, chain_system, user)
                stats.account(usage, chain_system + user, content)
                break
            except LLMError as e:
                if attempt >= cfg.retries:
                    with stats.lock:
                        stats.files_errored += 1
                    log(f"  ERROR chain {sink.file}:{sink.line}: {e}")
                else:
                    time.sleep(1.5 * (attempt + 1))
        if not content:
            continue
        findings = parse_chain_response(content, sink)

        # optional verify
        if cfg.verify and findings:
            kept = []
            for f in findings:
                f.setdefault("start_line", sink.line)
                verdict = verify_finding(cfg, file_texts.get(sink.file, ""), f,
                                         stats)
                with stats.lock:
                    stats.verified += 1
                if verdict is not None:
                    f["verify"] = {"verdict": verdict.get("verdict", ""),
                                   "is_real": bool(verdict.get("is_real")),
                                   "reasoning": verdict.get("reasoning", "")}
                    if not verdict.get("is_real") and not cfg.keep_fp:
                        with stats.lock:
                            stats.false_positives += 1
                        continue
                kept.append(f)
            findings = kept

        with _write_lock:
            for f in findings:
                f.setdefault("start_line", sink.line)
                f.setdefault("end_line", sink.line)
                _write_finding_record(out_fh, sink.file, f, cfg, "chain")
            out_fh.flush()
        with stats.lock:
            stats.findings += len(findings)
            for f in findings:
                stats.by_severity[f["severity"]] += 1
        if findings:
            log(f"  [chain] {sink.file}:{sink.line} -> "
                f"{len(findings)} chain finding(s)")
        elif cfg.verbose:
            log(f"  [chain] {sink.file}:{sink.line} -> no viable chain")


def build_cve_db(cfg: Config, root: str):
    """Assemble a composite vulnerability DB from all configured sources."""
    if OsvDatabase is None:
        return None
    import cve as cvemod
    providers = []

    if cfg.osv_db or cfg.osv_online:
        osv = OsvDatabase(online=cfg.osv_online, timeout=cfg.timeout)
        if cfg.osv_db:
            n = osv.load_dir(cfg.osv_db)
            log(f"OSV offline DB: {n} affected-package record(s) from {cfg.osv_db}")
        if cfg.osv_online:
            log("OSV online (api.osv.dev) ENABLED")
        providers.append(osv)

    if cfg.ghsa:
        if cfg.github_token:
            log("GHSA (GitHub Advisory, real-time) ENABLED")
            providers.append(cvemod.GhsaProvider(cfg.github_token, cfg.timeout))
        else:
            log("GHSA requested but no token -- set GITHUB_TOKEN; skipping")

    if cfg.nvd:
        log("NVD (NIST 2.0) ENABLED" +
            (" with API key" if cfg.nvd_api_key else " (unauthenticated, "
             "rate-limited to ~5 req/30s)"))
        providers.append(cvemod.NvdProvider(cfg.nvd_api_key, cfg.timeout))

    if cfg.native_audit:
        log("Native audit: running composer/npm/pip-audit/cargo audit ...")
        nap = cvemod.NativeAuditProvider(root, timeout=cfg.timeout)
        if nap.ran:
            log("  ran: " + "; ".join(nap.ran))
        else:
            log("  no audit tools found/applicable")
        providers.append(nap)

    if not providers:
        return None
    return cvemod.CompositeVulnDB(providers)


def run(cfg: Config) -> Stats:
    root = os.path.abspath(cfg.path)
    files = discover_files(cfg)
    log(f"Discovered {len(files)} candidate file(s) under {root}")
    log(f"Provider={cfg.provider}  Model={cfg.model}  "
        f"Workers={cfg.workers}  Output={cfg.out}")
    log("-" * 60)

    cve_db = build_cve_db(cfg, root)

    ctx_builder = None
    if cfg.with_imports and ContextBuilder is not None:
        ctx_builder = ContextBuilder(
            root, max_local_files=cfg.max_local_imports,
            char_budget=cfg.context_budget, cve_db=cve_db)
        log(f"Import context ON -- indexed {len(ctx_builder.deps)} "
            f"third-party dependency version(s) from manifests")

    skillset = None
    if cfg.skills and SkillSet is not None:
        skillset = SkillSet.from_specs(cfg.skills, total_budget=cfg.skill_budget)
        if len(skillset):
            log(f"Skills loaded ({len(skillset)}): {', '.join(skillset.names())}"
                " -- injected into the per-file review prompt")
        else:
            log(f"No usable skill guidance found in: {', '.join(cfg.skills)}")
            skillset = None

    if cfg.verify:
        log("Verify pass ON -- each finding gets an adversarial second review")

    stats = Stats()
    os.makedirs(os.path.dirname(os.path.abspath(cfg.out)) or ".", exist_ok=True)
    with open(cfg.out, "w", encoding="utf-8") as out_fh:
        if cfg.mode == "chain":
            run_chain(cfg, root, files, stats, out_fh, ctx_builder, cve_db,
                      skillset)
        elif cfg.workers <= 1:
            for p in files:
                scan_one_file(cfg, root, p, stats, out_fh, ctx_builder, skillset)
        else:
            with concurrent.futures.ThreadPoolExecutor(cfg.workers) as ex:
                futs = [ex.submit(scan_one_file, cfg, root, p, stats,
                                  out_fh, ctx_builder, skillset)
                        for p in files]
                for _ in concurrent.futures.as_completed(futs):
                    pass

        # ----- project-wide vulnerable-dependency findings (OSV/GHSA) -----
        if cfg.mode != "chain" and ctx_builder is not None and cve_db is not None:
            emit_dependency_findings(cfg, ctx_builder, stats, out_fh)
    return stats


# OSV severity string -> our severity bucket
_OSV_SEV = {
    "CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium",
    "MEDIUM": "Medium", "LOW": "Low",
}


def emit_dependency_findings(cfg: Config, ctx_builder, stats: Stats,
                             out_fh) -> None:
    rows = ctx_builder.dep_vulns()
    if not rows:
        return
    with _write_lock:
        for row in rows:
            worst = "Info"
            ids = []
            for v in row["vulns"]:
                sev = _OSV_SEV.get((v.severity or "").upper(), "High")
                if SEVERITY_ORDER[sev] < SEVERITY_ORDER[worst]:
                    worst = sev
                ids.append(v.short())
            fixed = next((v.fixed for v in row["vulns"] if v.fixed), "")
            rec = {
                "id": hashlib.sha1(
                    f"dep:{row['name']}:{row['version']}".encode()
                ).hexdigest()[:12],
                "type": "dependency",
                "file": f"{row['ecosystem']}:{row['name']}",
                "lines": None,
                "severity": worst,
                "description": f"Dependency {row['name']} {row['version']} "
                               f"({row['ecosystem']}) has "
                               f"{len(row['vulns'])} known vulnerability(ies).",
                "affected_code": f"{row['name']} == {row['version']}",
                "attack_path": "Depends on the CVE; an attacker exploits the "
                               "known flaw in this dependency version.",
                "evidence": " | ".join(ids[:8]),
                "confidence": "High",
                "recommendation": (f"Upgrade {row['name']} to {fixed} or later."
                                   if fixed else
                                   f"Upgrade {row['name']} to a patched version."),
                "cwe": "",
                "verify": None,
                "model": "cve-db",
                "provider": "+".join(s for s, on in (
                    ("osv-offline", bool(cfg.osv_db)),
                    ("osv-online", cfg.osv_online), ("ghsa", cfg.ghsa),
                    ("nvd", cfg.nvd), ("native-audit", cfg.native_audit))
                    if on) or "cve-db",
                "timestamp": now_iso(),
            }
            out_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        out_fh.flush()
    with stats.lock:
        stats.dep_findings += len(rows)
        stats.findings += len(rows)
        for row in rows:
            worst = min((_OSV_SEV.get((v.severity or "").upper(), "High")
                         for v in row["vulns"]), key=lambda s: SEVERITY_ORDER[s])
            stats.by_severity[worst] += 1
    log(f"  [dep] {len(rows)} vulnerable dependency(ies) flagged via OSV/GHSA")


# Approximate list prices, USD per 1M tokens (input, output). Used only when
# --price-in/--price-out are not given. Matched by substring of the model name.
# EDIT THESE to your provider's real rates -- they drift and proxies differ.
PRICE_TABLE = {
    "claude-opus": (15.0, 75.0),
    "claude-sonnet": (3.0, 15.0),
    "claude-haiku": (0.80, 4.0),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.0),
    "gpt-4.1": (2.0, 8.0),
    "o1": (15.0, 60.0),
    "o3": (2.0, 8.0),
    "deepseek": (0.27, 1.10),
    "gemini-1.5-pro": (1.25, 5.0),
    "gemini-1.5-flash": (0.075, 0.30),
}

LOCAL_PROVIDERS = ("ollama",)


def resolve_prices(cfg: Config) -> tuple[float, float, str]:
    """Return (price_in, price_out, source) USD per 1M tokens."""
    if cfg.price_in >= 0 or cfg.price_out >= 0:
        return max(cfg.price_in, 0.0), max(cfg.price_out, 0.0), "user"
    if cfg.provider in LOCAL_PROVIDERS:
        return 0.0, 0.0, "local"
    m = cfg.model.lower()
    for key, (pi, po) in PRICE_TABLE.items():
        if key in m:
            return pi, po, f"table:{key}"
    return 0.0, 0.0, "unknown"


def print_summary(cfg: Config, stats: Stats, elapsed: float) -> None:
    log("-" * 60)
    log("SCAN COMPLETE")
    log(f"  Files scanned : {stats.files_scanned}")
    log(f"  Files skipped : {stats.files_skipped}")
    log(f"  Files errored : {stats.files_errored}")
    log(f"  Findings      : {stats.findings}")
    for sev in SEVERITY_ORDER:
        if stats.by_severity[sev]:
            log(f"      {sev:<9}: {stats.by_severity[sev]}")
    if stats.dep_findings:
        log(f"  Vulnerable deps (OSV/GHSA): {stats.dep_findings}")
    if stats.verified:
        log(f"  Verified findings : {stats.verified}"
            f"  (dropped {stats.false_positives} false positive(s))")

    # ----- token usage + estimated cost -----
    est = "~" if stats.usage_estimated else ""
    log(f"  Model calls   : {stats.calls}")
    log(f"  Tokens        : {est}{stats.input_tokens:,} in + "
        f"{est}{stats.output_tokens:,} out = "
        f"{est}{stats.input_tokens + stats.output_tokens:,} total")
    pi, po, src = resolve_prices(cfg)
    cost = stats.input_tokens / 1e6 * pi + stats.output_tokens / 1e6 * po
    if src == "local":
        log("  Est. cost     : $0.00 (local model)")
    elif pi == 0 and po == 0:
        log("  Est. cost     : unknown -- set --price-in/--price-out "
            "(USD per 1M tokens) for your endpoint")
    else:
        approx = "~" if (stats.usage_estimated or src.startswith("table")) else ""
        note = f" [{src}: ${pi}/${po} per 1M in/out]"
        log(f"  Est. cost     : {approx}${cost:.4f}{note}")
    log(f"  Elapsed       : {elapsed:.1f}s")
    log(f"  Report (NDJSON): {os.path.abspath(cfg.out)}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanner.py",
        description="Local-AI file-by-file source vulnerability harness "
                    "-> NDJSON report.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("path", nargs="?", default=_env("AVH_PATH", None),
                   help="File or directory to scan (or set AVH_PATH in .env)")
    p.add_argument("-o", "--out", default=_env("AVH_OUT", "findings.ndjson"),
                   help="Output NDJSON path")
    p.add_argument("--provider", choices=["ollama", "openai", "custom"],
                   default=_env("AVH_PROVIDER", "ollama"))
    p.add_argument("--model", default=_env("AVH_MODEL", "qwen3:30b"),
                   help="Model name/tag (e.g. qwen3:30b, qwen2.5-coder:32b)")
    p.add_argument("--base-url", default=_env("AVH_BASE_URL", ""),
                   help="Override endpoint. ollama default "
                        "http://localhost:11434 ; openai default .../v1")
    p.add_argument("--api-key",
                   default=_env("LLM_API_KEY", _env("AVH_API_KEY", "")),
                   help="Bearer token for openai-compatible providers "
                        "(or set LLM_API_KEY)")
    p.add_argument("--header", action="append", default=[],
                   metavar="K:V",
                   help="Extra HTTP header (repeatable), e.g. "
                        "--header 'api-key: XXX'. Overrides Authorization. "
                        "Also settable as AVH_HEADERS JSON in .env")
    p.add_argument("--structured", choices=["schema", "json_object", "off"],
                   default=_env("AVH_STRUCTURED", "schema"),
                   help="OpenAI structured-output mode. Use 'json_object' or "
                        "'off' for Anthropic/Claude proxies that reject "
                        "json_schema (fixes HTTP 403 / hangs).")
    p.add_argument("--ext", default=_env("AVH_EXT", ""),
                   help="Comma-separated extensions to include "
                        "(default: common source types). Use '*' for all.")
    p.add_argument("--include", default=_env("AVH_INCLUDE", ""),
                   help="Comma-separated glob(s); only matching paths scanned")
    p.add_argument("--exclude", default=_env("AVH_EXCLUDE", ""),
                   help="Comma-separated glob(s) to exclude")
    p.add_argument("--num-ctx", type=int, default=_env_int("AVH_NUM_CTX", 16384),
                   help="Context window tokens (Ollama num_ctx)")
    p.add_argument("--temperature", type=float,
                   default=_env_float("AVH_TEMPERATURE", 0.1))
    p.add_argument("--max-file-bytes", type=int,
                   default=_env_int("AVH_MAX_FILE_BYTES", 400_000))
    p.add_argument("--chunk-lines", type=int,
                   default=_env_int("AVH_CHUNK_LINES", 700))
    p.add_argument("--chunk-overlap", type=int,
                   default=_env_int("AVH_CHUNK_OVERLAP", 40))
    p.add_argument("--workers", type=int, default=_env_int("AVH_WORKERS", 1),
                   help="Parallel files (keep low for a single local GPU)")
    p.add_argument("--timeout", type=int, default=_env_int("AVH_TIMEOUT", 600))
    p.add_argument("--retries", type=int, default=_env_int("AVH_RETRIES", 2))
    p.add_argument("--min-confidence", choices=["High", "Medium", "Low"],
                   default=_env("AVH_MIN_CONFIDENCE", "Low"),
                   help="Drop findings below this confidence")
    p.add_argument("--no-imports", action="store_true",
                   default=_env_bool("AVH_NO_IMPORTS", False),
                   help="Disable import context (local sigs + dep versions)")
    p.add_argument("--context-budget", type=int,
                   default=_env_int("AVH_CONTEXT_BUDGET", 6000),
                   help="Max chars of import context injected per file")
    p.add_argument("--max-local-imports", type=int,
                   default=_env_int("AVH_MAX_LOCAL_IMPORTS", 10),
                   help="Max local imported files to pull signatures from")
    p.add_argument("--verify", action="store_true",
                   default=_env_bool("AVH_VERIFY", False),
                   help="Second adversarial pass: model re-judges each finding "
                        "to cut false positives (doubles model calls)")
    p.add_argument("--keep-fp", action="store_true",
                   default=_env_bool("AVH_KEEP_FP", False),
                   help="With --verify, keep findings judged false positive "
                        "(annotated) instead of dropping them")
    p.add_argument("--osv-db", default=_env("AVH_OSV_DB", ""),
                   help="Path to a local OSV/GHSA JSON dir for offline CVE "
                        "lookup of dependencies")
    p.add_argument("--osv-online", action="store_true",
                   default=_env_bool("AVH_OSV_ONLINE", False),
                   help="Query api.osv.dev online (sends package names off-box)")
    p.add_argument("--ghsa", action="store_true",
                   default=_env_bool("AVH_GHSA", False),
                   help="GitHub Advisory DB (real-time GraphQL). Needs "
                        "GITHUB_TOKEN.")
    p.add_argument("--nvd", action="store_true",
                   default=_env_bool("AVH_NVD", False),
                   help="NVD (NIST 2.0) REST lookups. Optional NVD_API_KEY.")
    p.add_argument("--native-audit", action="store_true",
                   default=_env_bool("AVH_NATIVE_AUDIT", False),
                   help="Run the project's own auditors (composer/npm/pip-audit/"
                        "cargo audit) and ingest results")
    p.add_argument("--mode", choices=["file", "chain"],
                   default=_env("AVH_MODE", "file"),
                   help="file = per-file review (default); chain = whole-program "
                        "gadget/deserialization chain analysis")
    p.add_argument("--chain-budget", type=int,
                   default=_env_int("AVH_CHAIN_BUDGET", 60000),
                   help="Max chars of gadget context per sink (chain mode)")
    p.add_argument("--max-chains", type=int,
                   default=_env_int("AVH_MAX_CHAINS", 20),
                   help="Max deserialization sinks to analyze (chain mode)")
    p.add_argument("--skill", action="append", default=[], metavar="PATH",
                   help="Inject an external SKILL.md / .md knowledge pack into "
                        "the per-file review prompt (repeatable; may be a file "
                        "or a dir). Also AVH_SKILLS (comma-separated) in .env")
    p.add_argument("--skill-budget", type=int,
                   default=_env_int("AVH_SKILL_BUDGET", 80000),
                   help="Max chars of skill guidance injected per file (also "
                        "caps each skill). Default 80k (~20k tokens) suits "
                        "large-context models; lower it for small local ctx.")
    p.add_argument("--price-in", type=float,
                   default=_env_float("AVH_PRICE_IN", -1.0),
                   help="USD per 1M input tokens (for cost estimate). "
                        "Auto by model if unset; 0 for local/free.")
    p.add_argument("--price-out", type=float,
                   default=_env_float("AVH_PRICE_OUT", -1.0),
                   help="USD per 1M output tokens (for cost estimate)")
    p.add_argument("-v", "--verbose", action="store_true",
                   default=_env_bool("AVH_VERBOSE", False))
    return p


def _parse_headers(a: argparse.Namespace) -> dict:
    headers: dict = {}
    raw = os.environ.get("AVH_HEADERS", "").strip()
    if raw:
        try:
            headers.update(json.loads(raw))
        except json.JSONDecodeError:
            log("warning: AVH_HEADERS is not valid JSON; ignoring")
    for h in a.header:
        k, sep, v = h.partition(":")
        if sep:
            headers[k.strip()] = v.strip()
    return {str(k): str(v) for k, v in headers.items()}


def cfg_from_args(a: argparse.Namespace) -> Config:
    if a.ext.strip() == "*":
        exts: list[str] = []
    elif a.ext.strip():
        exts = [e if e.startswith(".") else "." + e
                for e in (x.strip() for x in a.ext.split(",")) if e]
    else:
        exts = list(DEFAULT_EXTS)
    return Config(
        path=a.path, out=a.out, provider=a.provider, model=a.model,
        base_url=a.base_url, api_key=a.api_key,
        extra_headers=_parse_headers(a), structured=a.structured, exts=exts,
        include=[g.strip() for g in a.include.split(",") if g.strip()],
        exclude=[g.strip() for g in a.exclude.split(",") if g.strip()],
        num_ctx=a.num_ctx, temperature=a.temperature,
        max_file_bytes=a.max_file_bytes, chunk_lines=a.chunk_lines,
        chunk_overlap=a.chunk_overlap, workers=a.workers, timeout=a.timeout,
        retries=a.retries, min_confidence=a.min_confidence, verbose=a.verbose,
        with_imports=not a.no_imports, context_budget=a.context_budget,
        max_local_imports=a.max_local_imports, verify=a.verify,
        keep_fp=a.keep_fp, osv_db=a.osv_db, osv_online=a.osv_online,
        ghsa=a.ghsa, github_token=_env("GITHUB_TOKEN", _env("AVH_GITHUB_TOKEN", "")),
        nvd=a.nvd, nvd_api_key=_env("NVD_API_KEY", _env("AVH_NVD_API_KEY", "")),
        native_audit=a.native_audit,
        mode=a.mode, chain_budget=a.chain_budget, max_chains=a.max_chains,
        skills=(a.skill or [s.strip() for s in
                _env("AVH_SKILLS", "").split(",") if s.strip()]),
        skill_budget=a.skill_budget,
        price_in=a.price_in, price_out=a.price_out,
    )


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # Allow --env-file PATH (peeked before argparse so its values seed defaults).
    env_path = ".env"
    if "--env-file" in raw:
        i = raw.index("--env-file")
        if i + 1 < len(raw):
            env_path = raw[i + 1]
            del raw[i:i + 2]
    loaded = load_dotenv(env_path)

    args = build_parser().parse_args(raw)
    if loaded and args.verbose:
        log(f"Loaded {loaded} setting(s) from {env_path}")
    cfg = cfg_from_args(args)
    if not cfg.path:
        log("error: no target path given (pass a path argument or set "
            "AVH_PATH in .env)")
        return 2
    if not os.path.exists(cfg.path):
        log(f"error: path not found: {cfg.path}")
        return 2
    t0 = time.time()
    try:
        stats = run(cfg)
    except KeyboardInterrupt:
        log("\nInterrupted.")
        return 130
    print_summary(cfg, stats, time.time() - t0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
