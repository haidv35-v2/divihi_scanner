#!/usr/bin/env python3
"""
chain.py — gadget / deserialization CHAIN discovery for the vuln harness.

The per-file scanner is blind to whole-program gadget chains (POP chains in PHP,
Java/.NET gadget chains, Python pickle chains) because a chain spans many classes
in many files. This module turns that whole-program problem into a *directed*
multi-file prompt:

  1. grep the whole repo for deserialization SINKS  (unserialize, pickle.loads,
     ObjectInputStream.readObject, BinaryFormatter, Marshal.load, yaml.load, ...)
  2. grep for GADGET candidates: files containing magic/callback methods that a
     chain can pivot through (__wakeup/__destruct/__toString, __reduce__/
     __setstate__, readObject/readResolve, [Serializable]/OnDeserialized, ...)
  3. for each sink, assemble the sink context + the gadget-bearing classes of the
     same language (bounded by a char budget) into ONE prompt and ask the model
     to construct and assess an exploitable chain.

Dependency-free. Returns work items; the model call + NDJSON writing stay in
scanner.py so all providers / verify / report reuse applies.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# ext -> language bucket used for grouping sinks with same-language gadgets
CHAIN_LANG = {
    ".php": "php",
    ".py": "python",
    ".java": "java", ".kt": "java", ".scala": "java",
    ".cs": "csharp",
    ".rb": "ruby",
    ".js": "node", ".ts": "node", ".jsx": "node", ".tsx": "node",
    ".mjs": "node", ".cjs": "node",
}

# --- deserialization sinks (untrusted-input entry points) ------------------ #
SINK_PATTERNS = {
    "php": [
        r"\bunserialize\s*\(", r"\byaml_parse\s*\(",
        r"->\s*unserialize\s*\(", r"\bmaybe_unserialize\s*\(",
    ],
    "python": [
        r"\bpickle\.loads?\s*\(", r"\bcPickle\.loads?\s*\(",
        r"\b_pickle\.loads?\s*\(", r"\bmarshal\.loads?\s*\(",
        r"\byaml\.load\s*\(", r"\bjsonpickle\.decode\s*\(",
        r"\bshelve\.open\s*\(", r"\bdill\.loads?\s*\(",
    ],
    "java": [
        r"\breadObject\s*\(", r"\bObjectInputStream\b", r"\breadUnshared\s*\(",
        r"\bXMLDecoder\b", r"\bXStream\b", r"\.fromXML\s*\(",
        r"enableDefaultTyping\s*\(", r"@JsonTypeInfo",
        r"new\s+Yaml\s*\(", r"\.readValue\s*\(",
    ],
    "csharp": [
        r"\bBinaryFormatter\b", r"\bLosFormatter\b", r"\bObjectStateFormatter\b",
        r"\bNetDataContractSerializer\b", r"\bSoapFormatter\b",
        r"TypeNameHandling", r"\bJavaScriptSerializer\b",
        r"\bfastJSON\b", r"\bXmlSerializer\b",
    ],
    "ruby": [
        r"\bMarshal\.load\b", r"\bYAML\.load\b", r"\bOj\.load\b",
        r"\.constantize\b",
    ],
    "node": [
        r"node-serialize", r"\bunserialize\s*\(", r"\bfuncster\b",
        r"serialize-javascript", r"\beval\s*\(", r"\bvm\.runIn",
    ],
}

# --- gadget candidate markers (chain pivot points) ------------------------- #
GADGET_PATTERNS = {
    "php": [
        r"function\s+__wakeup", r"function\s+__destruct", r"function\s+__toString",
        r"function\s+__call", r"function\s+__get", r"function\s+__set",
        r"function\s+__unserialize", r"function\s+offsetGet",
        r"function\s+__invoke",
    ],
    "python": [
        r"def\s+__reduce__", r"def\s+__reduce_ex__", r"def\s+__setstate__",
        r"def\s+__getstate__", r"def\s+__getattr__", r"def\s+__wrapped__",
        r"def\s+__class_getitem__",
    ],
    "java": [
        r"\breadObject\s*\(", r"\breadResolve\s*\(", r"\breadExternal\s*\(",
        r"\bfinalize\s*\(", r"implements\s+Serializable",
        r"InvocationHandler", r"\bcompareTo\s*\(", r"\bhashCode\s*\(",
        r"\btoString\s*\(",
    ],
    "csharp": [
        r"\[Serializable\]", r"OnDeserialized", r"OnDeserializing",
        r"ISerializable", r"IDeserializationCallback", r"GetObjectData",
    ],
    "ruby": [
        r"def\s+method_missing", r"def\s+marshal_load", r"def\s+_load",
        r"def\s+init_with",
    ],
    "node": [
        r"function.*\)\s*\{", r"=>", r"toString\s*\(", r"valueOf\s*\(",
    ],
}


@dataclass
class Sink:
    file: str          # repo-relative path
    line: int
    lang: str
    snippet: str


@dataclass
class GadgetFile:
    file: str          # repo-relative
    lang: str
    markers: list[str] = field(default_factory=list)
    count: int = 0


def _find(patterns: list[str], text: str):
    for pat in patterns:
        for m in re.finditer(pat, text):
            yield pat, m.start()


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_sinks_and_gadgets(file_texts: dict[str, str]):
    """file_texts: {rel_path: content}. Returns (sinks, gadgets_by_lang)."""
    sinks: list[Sink] = []
    gadgets: dict[str, list[GadgetFile]] = {}
    for rel, text in file_texts.items():
        ext = os.path.splitext(rel)[1].lower()
        lang = CHAIN_LANG.get(ext)
        if not lang:
            continue
        for _pat, pos in _find(SINK_PATTERNS.get(lang, []), text):
            ln = _line_of(text, pos)
            line_txt = text.split("\n")[ln - 1].strip()[:200]
            sinks.append(Sink(file=rel, line=ln, lang=lang, snippet=line_txt))
        markers = []
        for pat in GADGET_PATTERNS.get(lang, []):
            hits = len(re.findall(pat, text))
            if hits:
                markers.append(f"{pat.strip()}(x{hits})")
        if markers and lang != "node":  # node markers too generic; skip listing
            gadgets.setdefault(lang, []).append(
                GadgetFile(file=rel, lang=lang, markers=markers,
                           count=sum(int(m.split("x")[-1].rstrip(")"))
                                     for m in markers)))
    for lang in gadgets:
        gadgets[lang].sort(key=lambda g: g.count, reverse=True)
    return sinks, gadgets


def _numbered_window(text: str, center_line: int, margin: int) -> str:
    lines = text.split("\n")
    lo = max(1, center_line - margin)
    hi = min(len(lines), center_line + margin)
    return "\n".join(f"{i}| {lines[i - 1]}" for i in range(lo, hi + 1))


def _extract_gadget_regions(text: str, lang: str, max_chars: int) -> str:
    """Keep only gadget-relevant regions of a class file to save budget."""
    lines = text.split("\n")
    keep = set()
    pats = GADGET_PATTERNS.get(lang, [])
    # always keep the top of file (class/namespace/use declarations)
    for i in range(min(40, len(lines))):
        keep.add(i)
    for i, ln in enumerate(lines):
        if any(re.search(p, ln) for p in pats) or \
           re.search(r"\b(class|namespace|package|use|import)\b", ln):
            for j in range(max(0, i - 1), min(len(lines), i + 30)):
                keep.add(j)
    out = []
    prev = -2
    for i in sorted(keep):
        if i > prev + 1:
            out.append("   ...")
        out.append(f"{i + 1}| {lines[i]}")
        prev = i
    body = "\n".join(out)
    return body[:max_chars]


def build_chain_context(sink: Sink, gadget_files: list[GadgetFile],
                        file_texts: dict[str, str], *, budget: int,
                        dep_note: str = "") -> str:
    """Assemble the multi-file context string for one sink."""
    parts: list[str] = []
    if dep_note:
        parts.append("KNOWN-VULNERABLE DESERIALIZATION LIBRARIES IN THIS "
                     "PROJECT (usable as gadget sources):\n" + dep_note)

    sink_text = file_texts.get(sink.file, "")
    parts.append(f"=== SINK FILE: {sink.file} (deserialization at line "
                 f"{sink.line}: `{sink.snippet}`) ===\n"
                 + _numbered_window(sink_text, sink.line, 60))

    used = sum(len(p) for p in parts)
    parts.append("=== CANDIDATE GADGET CLASSES (same language, magic/callback "
                 "methods that a chain can pivot through) ===")
    for gf in gadget_files:
        if gf.file == sink.file:
            continue
        if used >= budget:
            parts.append(f"   ...(gadget budget reached; {len(gadget_files)} "
                         "candidate files total, some omitted)")
            break
        region = _extract_gadget_regions(file_texts.get(gf.file, ""),
                                         gf.lang, max_chars=budget // 6)
        block = (f"\n--- GADGET FILE: {gf.file}  [{', '.join(gf.markers[:6])}] ---\n"
                 + region)
        parts.append(block)
        used += len(block)
    return "\n\n".join(parts)


@dataclass
class ChainJob:
    sink: Sink
    context: str
    n_gadget_files: int
