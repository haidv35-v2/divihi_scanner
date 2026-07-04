#!/usr/bin/env python3
"""
skills.py — plug external SKILL.md / knowledge packs into the per-file review.

The harness calls a raw model endpoint, so it can't *invoke* Claude Code skills.
But a skill is just markdown knowledge (vuln checklists, language-specific
patterns, secure-coding rules). This module loads those files and injects their
guidance into the reviewer's system prompt for each file — optionally scoped to
matching file extensions — so the local model reviews with that expertise.

A knowledge file may carry YAML-ish frontmatter:

    ---
    name: php-security
    description: PHP-specific injection & POP-chain checklist
    extensions: php, phtml          # optional; omit = applies to all files
    ---
    # ... your checklist / patterns / rules in markdown ...

Plain .md files (no frontmatter) are loaded as-is and apply to all files.
Dependency-free.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field


@dataclass
class SkillDoc:
    name: str
    body: str
    exts: list[str] = field(default_factory=list)  # empty => applies to all

    def applies(self, ext: str) -> bool:
        return not self.exts or ext.lstrip(".").lower() in self.exts


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """Return (meta, body). Supports a leading --- ... --- block."""
    if not text.startswith("---"):
        return {}, text
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", text, re.S)
    if not m:
        return {}, text
    meta: dict = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.strip().startswith("#"):
            k, _, v = line.partition(":")
            meta[k.strip().lower()] = v.strip()
    return meta, m.group(2)


def _exts_from_meta(meta: dict) -> list[str]:
    raw = meta.get("extensions") or meta.get("applies_to") or ""
    raw = raw.strip().strip("[]")
    return [e.strip().lstrip(".").lower()
            for e in re.split(r"[,\s]+", raw) if e.strip()]


def load_skill_file(path: str, *, per_skill_cap: int = 80000) -> SkillDoc | None:
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    meta, body = _parse_frontmatter(text)
    body = body.strip()
    if not body:
        return None
    name = meta.get("name") or os.path.splitext(os.path.basename(path))[0]
    if len(body) > per_skill_cap:
        body = body[:per_skill_cap] + "\n... (guidance truncated)"
    return SkillDoc(name=name, body=body, exts=_exts_from_meta(meta))


def discover_skill_paths(spec: str) -> list[str]:
    """A spec may be a .md file, or a directory (SKILL.md + top-level *.md)."""
    out: list[str] = []
    if os.path.isfile(spec):
        out.append(spec)
    elif os.path.isdir(spec):
        skill_md = os.path.join(spec, "SKILL.md")
        if os.path.isfile(skill_md):
            out.append(skill_md)
        for fn in sorted(os.listdir(spec)):
            full = os.path.join(spec, fn)
            if fn.lower().endswith(".md") and fn != "SKILL.md" \
                    and os.path.isfile(full):
                out.append(full)
    return out


class SkillSet:
    """Loaded knowledge packs, queryable by file extension."""

    def __init__(self, docs: list[SkillDoc], *, total_budget: int = 80000):
        self.docs = docs
        self.total_budget = total_budget

    @classmethod
    def from_specs(cls, specs: list[str], *, per_skill_cap: int | None = None,
                   total_budget: int = 80000) -> "SkillSet":
        # Default the per-skill cap to the whole budget so a single large skill
        # (e.g. a full HUNT-* playbook) is not silently truncated at 6 KB.
        if per_skill_cap is None:
            per_skill_cap = total_budget
        seen: set[str] = set()
        docs: list[SkillDoc] = []
        for spec in specs:
            for p in discover_skill_paths(spec):
                ap = os.path.abspath(p)
                if ap in seen:
                    continue
                seen.add(ap)
                doc = load_skill_file(p, per_skill_cap=per_skill_cap)
                if doc:
                    docs.append(doc)
        return cls(docs, total_budget=total_budget)

    def __len__(self) -> int:
        return len(self.docs)

    def names(self) -> list[str]:
        return [d.name for d in self.docs]

    def guidance_for(self, ext: str) -> str:
        """Concatenated guidance from all skills applicable to this extension."""
        applicable = [d for d in self.docs if d.applies(ext)]
        if not applicable:
            return ""
        blocks: list[str] = []
        used = 0
        for d in applicable:
            block = f"### Skill: {d.name}\n{d.body}"
            if used + len(block) > self.total_budget:
                remaining = self.total_budget - used
                if remaining > 400:
                    blocks.append(block[:remaining] + "\n... (truncated)")
                break
            blocks.append(block)
            used += len(block)
        if not blocks:
            return ""
        return ("ADDITIONAL REVIEW GUIDANCE (apply these expert checklists/"
                "patterns while reviewing this file):\n\n" + "\n\n".join(blocks))
