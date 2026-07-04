# ai-vuln-harness

A **local-AI, file-by-file source code vulnerability review harness**, modeled on
projectblack.io's "Local AI for Cyber Security" approach:

> For each source file → local model reviews ONE file (+ line numbers) →
> structured findings → streamed to an NDJSON report.

Deliberately **decomposed** (one file per model call) instead of "review the whole
repo at once" — the blog's key finding was that *once the model is pointed at the
right file, it spots the bug almost every time*. No third-party Python deps.

## Files
- `scanner.py` — the harness (discover → chunk → prompt model → verify → write NDJSON)
- `context.py` — builds per-file **import context** (see below)
- `cve.py` — offline/online **OSV/GHSA** CVE lookup for dependencies
- `report.py` — render NDJSON into Markdown or HTML
- `.env.example` — copy to `.env` to configure without CLI flags
- `samples/` — deliberately vulnerable files + a mini OSV DB to smoke-test with

## Pipeline
```
discover files
  └─ per file:
       build import context (local signatures + dep versions + known CVEs)
       chunk (line-numbered, overlapping windows)
       PASS 1  -> model finds vulnerabilities        (SYSTEM_PROMPT)
       PASS 2  -> model adversarially re-judges each  (--verify)  -> drops FPs
       write surviving findings to NDJSON
  └─ end: emit project-wide vulnerable-dependency findings (OSV/GHSA)
```

## Second (verify) pass — cut false positives
`--verify` runs a second model call per finding with a **skeptical reviewer**
prompt ("assume false positive until the code proves otherwise"). Each finding
gets a `verify` object (`verdict`, `is_real`, `reasoning`); findings judged
false-positive are dropped (keep them annotated with `--keep-fp`). Severity /
confidence may be adjusted by the reviewer. Roughly doubles model calls.

## Dependency CVE lookup (OSV / GHSA)
`--osv-db ./osv-db` reads a local OSV JSON database (fully **offline**), matches
each manifest dependency's version against known-vulnerable ranges, and:
  - annotates the import context (`[KNOWN VULNS] CVE-… fixed in …`) so PASS 1
    reasons about it, and
  - emits a `type:"dependency"` finding per vulnerable package at the end.

Populate the offline DB automatically with the bundled fetcher (stdlib only,
no `gcloud`/`gsutil` needed) — it downloads the official OSV.dev per-ecosystem
`all.zip` (which already includes GHSA) and extracts it:
```bash
python fetch_osv.py                       # PyPI npm Packagist -> ./osv-db
python fetch_osv.py PyPI npm Go RubyGems Maven -o ./osv-db
python fetch_osv.py --list                # list known ecosystem names
python scanner.py ./src --osv-db ./osv-db
```
Source: `https://osv-vulnerabilities.storage.googleapis.com/{ECOSYSTEM}/all.zip`
(full list at `.../ecosystems.txt`). Re-run periodically to refresh.

Or use `--osv-online` to query `api.osv.dev` live (sends package names off-box —
only when authorized).

### Fresher / additional CVE sources (merged + deduped by CVE id)
For newer advisories than a static OSV dump, add any of these — the scanner
queries all enabled sources and merges results:

| Flag | Source | Freshness | Auth |
|------|--------|-----------|------|
| `--osv-db ./osv-db` | OSV offline dump | snapshot (re-fetch to refresh) | none |
| `--osv-online` | api.osv.dev (live) | current | none |
| `--ghsa` | GitHub Advisory DB (GraphQL) | **real-time**, good version ranges | `GITHUB_TOKEN` |
| `--nvd` | NVD / NIST 2.0 (REST) | current, authoritative | optional `NVD_API_KEY` |
| `--native-audit` | project's own `composer audit` / `npm audit` / `pip-audit` / `cargo audit` | **freshest, exact to your lockfile** | tools installed |

```bash
# combine several — freshest possible coverage
GITHUB_TOKEN=ghp_xxx python scanner.py ./src \
    --osv-online --ghsa --nvd --native-audit -o findings.ndjson -v
```
`--native-audit` reflects your real lockfile exactly (it shells out to the
ecosystem's own auditor); `--ghsa`/`--nvd` are live API lookups per dependency.
All enabled sources are queried and **merged, deduped by CVE/GHSA id**; each
dependency finding records which sources it came from (e.g.
`provider: "osv-online+ghsa+nvd"`).

#### GHSA — GitHub Advisory Database (`--ghsa`)
Real-time, best version-range data for open-source packages.

1. Create a **classic Personal Access Token** at
   <https://github.com/settings/tokens> — **no scopes needed** (public advisory
   data is readable with any valid token; a fine-grained token with default
   read works too).
2. Export it and enable the source:
   ```bash
   export GITHUB_TOKEN=ghp_xxxxxxxx        # Windows PowerShell: $env:GITHUB_TOKEN="ghp_..."
   python scanner.py ./src --ghsa -o findings.ndjson -v
   ```
   Or put `GITHUB_TOKEN=ghp_xxx` / `AVH_GHSA=true` in `.env`.
- Queried per dependency via the GraphQL `securityVulnerabilities` API and
  cached. Ecosystems mapped automatically (PyPI→PIP, npm→NPM, Packagist→
  COMPOSER, Go, RubyGems, Maven, NuGet, crates.io→RUST, …).
- No token → the source is skipped with a warning (scan still runs).

#### NVD — NIST National Vulnerability Database (`--nvd`)
Authoritative CVE source; version matching via CPE ranges.

```bash
python scanner.py ./src --nvd -o findings.ndjson -v          # unauthenticated
export NVD_API_KEY=xxxx-xxxx ; python scanner.py ./src --nvd   # faster
```
- An API key is **optional** but recommended: request one at
  <https://nvd.nist.gov/developers/request-an-api-key>. Without it NVD rate-
  limits to ~5 requests / 30 s (the harness caches per package to stay under it);
  with a key it's ~50 / 30 s.
- Set `NVD_API_KEY` (or `AVH_NVD_API_KEY`) / `AVH_NVD=true` in `.env`.
- NVD maps packages by CPE product name, so it is noisier than OSV/GHSA — treat
  its hits as leads and rely on the `fixed`/range data to confirm.

#### Native audit — the project's own auditor (`--native-audit`)
Freshest and most precise: shells out to each ecosystem's official auditor over
your **real lockfiles** and ingests the results. Runs whatever is installed and
applicable; missing tools are skipped (never fails the scan).

| Ecosystem | Tool run | Needs | Install |
|-----------|----------|-------|---------|
| PHP | `composer audit --format=json` | `composer.lock` | ships with Composer 2.4+ |
| npm | `npm audit --json` | `package-lock.json` | ships with npm |
| Python | `pip-audit -f json -r requirements.txt` | `requirements.txt` | `pipx install pip-audit` |
| Rust | `cargo audit --json` | `Cargo.lock` | `cargo install cargo-audit` |

```bash
python scanner.py ./src --native-audit -o findings.ndjson -v
```
- It walks the repo (skipping `node_modules`/`vendor`), finds up to a few
  lockfile dirs per ecosystem, and runs the auditor there.
- Because the auditor already resolved the installed versions, its hits are
  returned as-is — the most trustworthy dependency findings you'll get.
- The verbose log prints exactly which auditors ran (`ran: composer audit @ …`).

## Import context (files reviewed *with* their dependencies)
Before each file is reviewed, the harness parses its `import`/`require`/`use`
statements and injects an **IMPORT CONTEXT** block into the prompt:

- **Local imports** are resolved to files inside the scan root; their
  **function/class signatures** (not full bodies) are included so the model can
  reason about taint flowing across files.
- **Third-party imports** are resolved to a **concrete version** read from the
  project manifest (`package.json`, `composer.json`, `requirements.txt`,
  `pyproject.toml`, `go.mod`, `Gemfile.lock`) — e.g. `flask @ 0.12.2` — so the
  model can flag versions with known CVEs and dangerous library APIs.

Supported languages: Python, JS/TS, PHP, Go, Java/Kotlin, Ruby.
Control it with `--no-imports`, `--context-budget`, `--max-local-imports`.

## 1. Run a local model

**Ollama** (recommended, native structured output):
```bash
ollama pull qwen3:30b          # or qwen2.5-coder:32b, deepseek-coder-v2, etc.
ollama serve                   # usually already running on :11434
```

## Configuration via `.env` (optional)
Copy `.env.example` → `.env`; it is **auto-loaded** from the current directory
on every run. Precedence: **CLI flag > `.env` > built-in default** (and real
environment variables override the file). Every flag has an `AVH_*` variable
(e.g. `AVH_PROVIDER`, `AVH_MODEL`, `AVH_BASE_URL`, `LLM_API_KEY`, `AVH_NUM_CTX`,
`AVH_VERIFY`, `AVH_OSV_DB`, `AVH_PATH`, …). Load a different file with
`--env-file prod.env`.

```bash
cp .env.example .env
# edit .env, then just:
python scanner.py ./src -o findings.ndjson
```

## Quick start (with a configured `.env`)
```bash
python scanner.py ./duong-dan-code -o findings.ndjson
python report.py findings.ndjson -f html
```

## 2. Scan

```bash
# Ollama (default provider) — full pipeline: imports + CVE + verify
python scanner.py /path/to/target-src \
    --model qwen3:30b \
    --num-ctx 32768 \
    --osv-db ./osv-db \
    --verify \
    -o findings.ndjson -v

# OpenAI-compatible endpoint (LM Studio / vLLM / llama.cpp server / gateway)
python scanner.py /path/to/target-src \
    --provider openai \
    --base-url http://localhost:1234/v1 \
    --model qwen2.5-coder-32b \
    --api-key "$LLM_API_KEY" \
    -o findings.ndjson
```

Smoke test against the bundled sample:
```bash
python scanner.py samples --model qwen3:30b -o findings.ndjson -v
```

## 3. Build a readable report
```bash
python report.py findings.ndjson -f html   # -> findings.html
python report.py findings.ndjson -f md      # -> findings.md
```
Filters (combine freely):
```bash
python report.py findings.ndjson --only-fp -f html          # only false positives
python report.py findings.ndjson --verdict true_positive     # confirmed only
python report.py findings.ndjson --type chain                # only gadget chains
python report.py findings.ndjson --min-severity High         # High + Critical
```

### Getting false positives into the report
The verify pass **drops** findings judged false-positive by default, so they
never reach `findings.ndjson`. To keep them, scan with `--keep-fp` (they are
written tagged `verify.verdict = "false_positive"`, `is_real: false`), then
isolate them:
```bash
python scanner.py ./src --verify --keep-fp -o findings.ndjson -v
python report.py findings.ndjson --only-fp -f html -o false-positives.html
```
Already-dropped FPs from a run without `--keep-fp` are gone — re-run to recover
them.

## Gadget / deserialization CHAIN mode
The per-file pass can't see whole-program gadget chains (PHP POP chains, Java/
.NET gadget chains, Python pickle chains) because a chain spans many classes in
many files. `--mode chain` handles that:

1. greps the whole repo for **deserialization sinks** (`unserialize`,
   `pickle.loads`, `ObjectInputStream.readObject`, `BinaryFormatter`,
   `Marshal.load`, `yaml.load`, …);
2. greps for **gadget candidates** — files with magic/callback methods a chain
   can pivot through (`__wakeup`/`__destruct`/`__toString`, `__reduce__`/
   `__setstate__`, `readObject`/`readResolve`, `[Serializable]`/`OnDeserialized`);
3. for each sink, assembles the sink context + the same-language gadget classes
   (plus any known-vulnerable deser libraries from OSV) into **one large prompt**
   and asks the model to construct a concrete chain (entry magic method → pivots
   → dangerous sink), citing each hop's `class::method (file:line)`.

```bash
python scanner.py ./src --mode chain --verify -o chains.ndjson -v
python report.py chains.ndjson -f html
```
Findings are written with `type:"chain"` and the step-by-step chain in
`attack_path` / `evidence`. Tune with `--chain-budget` (chars of gadget context
per sink) and `--max-chains` (max sinks analyzed). Best paired with a
large-context model (Claude, or Ollama `--num-ctx` 64k+).

## Inject skills / knowledge packs into the review (`--skill`)
You can feed external **SKILL.md files or any `.md` knowledge packs** (vuln
checklists, language-specific patterns, secure-coding rules) straight into the
per-file review prompt — the local model then reviews *with that expertise*.
Because the harness talks to a raw model endpoint (not Claude Code), it can't
*invoke* a skill; instead it **loads the skill's markdown and injects it** into
the reviewer's system prompt.

```bash
python scanner.py ./src --skill ./skillpacks --skill ./my-owasp-skill/SKILL.md \
    -o findings.ndjson -v
```
- `--skill` is repeatable and accepts a **file** (`.md` / `SKILL.md`) or a
  **directory** (loads its `SKILL.md` + top-level `*.md`). Also
  `AVH_SKILLS=path1,path2` in `.env`.
- **Scope by language** with frontmatter — a skill only applies to matching
  files (others are skipped for that file):
  ```markdown
  ---
  name: php-security
  extensions: php, phtml      # omit = applies to all files
  ---
  # your PHP injection / POP-chain checklist ...
  ```
- Plain `.md` files (no frontmatter) apply to all files.
- Applies to both `--mode file` and `--mode chain`. `--skill-budget` caps both
  each skill and the total injected per file — default **80 000 chars
  (~20k tokens)**, sized for large-context models (Claude, Qwen3-30B). A whole
  folder of HUNT-* playbooks fits; lower it for small local-context models. The
  verbose log lists which skills loaded.

### Static vs dynamic skills
The harness does **static source review**. If you feed a hunting skill written
for live/DAST testing (`curl`, `ffuf`, Burp Collaborator, OOB callbacks), those
runtime steps are **not executed** — but the sink patterns, attack-surface
signals, chain/bypass tables and **severity rubric** still sharpen the model's
detection and its `attack_path`/severity reasoning (e.g. it learns a
`php://filter` read is upgradeable to RCE → Critical). Two ways to use such a
skill:
- **As-is** — keep the full playbook; the model uses the source-relevant parts.
- **Trimmed** — a static-focused version (sinks + severity rubric + false-
  positive discipline) is smaller, cheaper, and less noisy per file.

### Cost note
Skill guidance is injected into **every reviewed file's** prompt, so input
tokens (and cost, shown in the summary) scale with skill size × files. That's
fine on big-context models; to trim on huge repos, **scope skills by
`extensions:`** so they only load for relevant files, or lower `--skill-budget`.

### Example: a folder of playbooks
```bash
# skillpacks/ holds hunt-lfi.md, hunt-rce.md, hunt-sqli.md, ... (each PHP-scoped)
python scanner.py ./src --skill ./skillpacks -o findings.ndjson -v
```

This is how you reuse your existing vuln-finding skills *inside* the sweep — the
knowledge does the guiding, the local model does the reading.

## Use as a Claude Code skill (`/vuln-harness`)
`SKILL.md` (in this folder) wraps the whole flow: run the sweep → triage &
rank → Claude deep-dives the top confirmed findings → optional `/graphify`
knowledge graph → HTML report. The local model does the broad grunt work; Claude
does the high-value verification.

Activate it by making it visible to Claude Code (copy or symlink into a skills
dir):
```bash
# Windows (PowerShell, from repo root)
mkdir "$env:USERPROFILE\.claude\skills\vuln-harness" -Force
copy SKILL.md "$env:USERPROFILE\.claude\skills\vuln-harness\SKILL.md"

# macOS/Linux
mkdir -p ~/.claude/skills/vuln-harness && ln -sf "$PWD/SKILL.md" ~/.claude/skills/vuln-harness/SKILL.md
```
Then in Claude Code: `/vuln-harness ./path/to/src`. It composes with the
built-in `security-review` (deep-dive) and `graphify` (visualize) skills.

## Troubleshooting
**HTTP 403 / hangs from a Claude/Anthropic proxy** (e.g. an OpenAI-compatible
gateway in front of Claude): those backends reject OpenAI's `response_format:
json_schema`. Set `--structured json_object` (or `off`) — the harness parses
JSON, fenced JSON, bare arrays, and even markdown `**key:** value` replies, so
it works with models that ignore structured-output hints.

**403 from a Cloudflare-fronted endpoint**: the harness already sends a browser
`User-Agent`. If a gateway needs a non-standard auth header, use
`--header 'api-key: XXX'` or `AVH_HEADERS={"api-key":"XXX"}`.

## NDJSON schema (one finding per line)
| field | meaning |
|-------|---------|
| `severity` | Critical / High / Medium / Low / Info |
| `description` | what the vulnerability is |
| `affected_code` | offending snippet with line numbers |
| `attack_path` | how an attacker reaches & exploits it |
| `evidence` | tainted source → dangerous sink reasoning |
| `confidence` | High / Medium / Low |
| `recommendation` | how to fix |
| _meta_ | `id, file, lines, cwe, model, provider, timestamp` |

## Useful flags
| flag | purpose |
|------|---------|
| `--ext php,py,js` | restrict file types (`--ext '*'` = all text files) |
| `--include "src/**"` / `--exclude "tests/**"` | glob filters |
| `--chunk-lines 700 --chunk-overlap 40` | window large files, overlap so cross-boundary bugs are seen whole |
| `--min-confidence Medium` | drop low-confidence noise |
| `--workers 2` | parallel files (keep low for one GPU) |
| `--num-ctx 32768` | model context window |
| `--temperature 0.1` | keep it deterministic |
| `--verify` / `--keep-fp` | second adversarial pass; drop / keep false positives |
| `--osv-db PATH` / `--osv-online` | offline / online OSV CVE lookup for dependencies |
| `--ghsa` / `--nvd` / `--native-audit` | extra CVE sources (GitHub Advisory / NIST NVD / project auditors) |
| `--mode chain` / `--chain-budget` / `--max-chains` | whole-program gadget-chain analysis |
| `--skill PATH` / `--skill-budget` | inject external SKILL.md / .md knowledge packs into the review |
| `--price-in` / `--price-out` | USD per 1M tokens for the cost estimate (auto by model if unset; 0 = local) |
| `--structured schema\|json_object\|off` | structured-output mode (use json_object/off for Claude proxies) |
| `--header 'K: V'` | extra HTTP header for non-standard gateway auth |

## Cost estimate
Every run prints token usage and an estimated cost:
```
  Model calls   : 812
  Tokens        : 2,150,400 in + 96,300 out = 2,246,700 total
  Est. cost     : ~$8.10 [table:claude-sonnet: $3.0/$15.0 per 1M in/out]
```
- Token counts are **real** when the endpoint reports usage (OpenAI `usage`,
  Ollama `prompt_eval_count`/`eval_count`); otherwise estimated (`~`, ≈ chars/4).
- Price is resolved as: `--price-in/--price-out` (or `AVH_PRICE_IN/OUT`) →
  `0` for local providers (Ollama) → a built-in approximate `PRICE_TABLE`
  matched by model name → else `unknown`.
- The table holds **approximate list prices** and proxies differ — set
  `--price-in`/`--price-out` (USD per 1M tokens) to your endpoint's real rates
  for an accurate figure. Verify (`--verify`) roughly doubles calls and cost.

## Notes / limitations (same as the blog)
- **Static, single-file review** → expect **false positives**; a human triages.
- **Weak on cross-file logic** (broken access control, multi-request flows) —
  each call sees only one file. Increase `--chunk-lines` / feed related files
  together if you extend the harness.
- Treat AI output as a **triage filter**, not a verdict. Verify every finding.
- Only scan code you are **authorized** to review.
