---
name: vuln-harness
description: >
  Local-AI source vulnerability sweep + triage. Runs the file-by-file harness
  (scanner.py) with a local/self-hosted model over a codebase, then triages the
  NDJSON findings, deep-dives the top confirmed issues, and optionally builds a
  knowledge graph. Trigger when the user wants to audit a codebase for security
  vulnerabilities offline, run "the vuln harness", or scan a repo for CVEs /
  injection / deserialization gadget chains.
---

# vuln-harness

Orchestrates the local-AI vulnerability harness in this directory and turns its
raw output into a prioritized, human-reviewed report. The local model does the
broad grunt work (cheap, private); you (Claude) do the high-value triage and
verification.

`$ARGUMENTS` is the target path to scan (a directory or file). If empty, ask the
user for it, or use `AVH_PATH` from `.env`.

## Step 0 — locate the tool
This skill lives next to `scanner.py`. Run all commands from the directory
containing `scanner.py` (the harness dir). If a `.env` exists there, it is
auto-loaded (provider, model, CVE sources, verify, etc.) — do not override its
settings unless the user asks.

## Step 1 — run the sweep
Run the harness over the target. Prefer settings already in `.env`; otherwise
use sensible defaults. Always enable the verify pass to cut false positives.

```bash
python scanner.py "<target>" --verify -o findings.ndjson -v
```

Guidance:
- If the user hints at deserialization / gadget chains / object injection, also
  run a second pass: `python scanner.py "<target>" --mode chain --verify -o chains.ndjson -v`
  and merge both files in triage.
- If dependency CVEs matter and no source is configured, add `--osv-online`
  (or `--ghsa`/`--nvd`/`--native-audit` if credentials/tools exist).
- Long scans: launch with `run_in_background: true` and wait for completion
  rather than blocking. Report progress from the stderr log.
- If the run errors with HTTP 403 / hangs on a Claude-style proxy, re-run with
  `--structured json_object` (see README Troubleshooting).

## Step 2 — triage + report (always)
Read `findings.ndjson` (one JSON object per line). Then produce a triage report:

1. **Rank** by: severity (Critical→Info), then `verify.verdict` (true_positive
   first, drop/deprioritize false_positive), then `confidence`.
2. **Group** by `type` (`code`, `chain`, `dependency`) and by `file`.
3. Present a **summary table**: severity | file:lines | one-line description |
   verify verdict | CWE.
4. Call out **hotspot files** (multiple findings) and any `type:"chain"`
   deserialization findings (highest impact).
5. Note counts and how many false positives the verify pass removed.

Be honest about limitations: these are static, single-file (or assembled-context)
findings — flag which ones still need manual confirmation.

## Step 3 — deep-dive the top findings (Claude verifies)
For each Critical/High finding with `verify.verdict == "true_positive"` (cap at
the top ~5 unless the user wants more):

1. **Open the actual file(s)** at the cited lines and read the real code — do
   not trust the finding blindly.
2. **Trace the data flow** from the untrusted source to the dangerous sink;
   confirm no sanitizer/guard breaks the path. For `type:"chain"` findings,
   walk each gadget hop in the referenced files.
3. Produce, per confirmed issue: a concrete **exploitation sketch** (example
   malicious input / request), the **precise root cause**, and a **specific
   fix** (code-level).
4. If the working tree has a relevant git diff, you may invoke the
   `security-review` skill to deep-review those changes with Claude.
5. Downgrade or discard anything you cannot substantiate from the real code,
   and say so.

## Step 4 — knowledge graph (optional)
Offer to visualize the landscape: invoke the `graphify` skill on
`findings.ndjson` to cluster findings into communities (by file / CWE / chain)
and produce an HTML + JSON graph. Do this when there are many findings or the
user wants an overview.

## Step 5 — render (optional)
Offer the shareable report:
```bash
python report.py findings.ndjson -f html   # -> findings.html
```

## Output
End with: (a) the ranked summary table, (b) deep-dive write-ups for confirmed
top issues with fixes, (c) pointers to `findings.ndjson` / `findings.html` /
graph. Keep it actionable — the user should know exactly what to fix first.
