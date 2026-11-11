"""Deterministic lexical scanner.

Turns raw prompt/response text into an ordered stream of security events.

The scanner is deliberately *not* an LLM: it is a small set of regular
expressions plus decoding checks, so its behaviour is fully reproducible
and can be exhaustively checked by the verifier (see ``verifier.py``).

Event kinds
-----------
SECRET       text matching a configured secret pattern (API key, token, ...)
INSTRUCTION  an instruction-like phrase inside untrusted content
FAKE_SYSTEM  a fake system-role marker (``[SYSTEM]``, ``System:``, ...)
ENCODED      a base64 / hex blob that decodes to printable text
TOOL_CALL    a tool/function-call marker
CONFIRMED    an explicit user confirmation ("yes, go ahead", "I confirm", ...)
BENIGN       no suspicious content found (emitted when nothing else matches)

Overlapping matches are resolved greedily: earliest start wins, ties go to
the higher-priority kind, then to the longer match.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

SECRET = "SECRET"
INSTRUCTION = "INSTRUCTION"
FAKE_SYSTEM = "FAKE_SYSTEM"
ENCODED = "ENCODED"
TOOL_CALL = "TOOL_CALL"
CONFIRMED = "CONFIRMED"
BENIGN = "BENIGN"

ALL_EVENTS = [SECRET, INSTRUCTION, FAKE_SYSTEM, ENCODED, TOOL_CALL, CONFIRMED, BENIGN]

# Priority for overlap resolution (lower number wins).
_PRIORITY = {
    SECRET: 0,
    FAKE_SYSTEM: 1,
    TOOL_CALL: 2,
    INSTRUCTION: 3,
    ENCODED: 4,
    CONFIRMED: 5,
}

# ---------------------------------------------------------------------------
# Pattern libraries (defaults; a Policy may supply its own secret patterns)
# ---------------------------------------------------------------------------

DEFAULT_SECRET_PATTERNS = [
    r"SECRET-[A-Za-z0-9]{6,}",
    r"sk-[A-Za-z0-9]{16,}",
    r"AKIA[0-9A-Z]{16}",
    r"(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9\-_]{8,}",
    r"(?i)password\s*[:=]\s*\S{8,}",
]

INSTRUCTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",
    r"(?i)disregard\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",
    r"(?i)forget\s+(your|all|the)\s+instructions?",
    r"(?i)you\s+are\s+now\b",
    r"(?i)override\s+(your|the)\s+instructions?",
    r"(?i)reveal\s+(the\s+)?(system\s+prompt|your\s+instructions|secret)",
    r"(?i)output\s+(the\s+)?(system\s+prompt|your\s+instructions)",
    r"(?i)output\s+(the\s+)?(secret|password|key)\b",
    r"(?i)do\s+not\s+follow\s+(your|the)\s+instructions?",
    r"(?i)pretend\s+(you\s+are|to\s+be)\b",
    r"(?i)\bact\s+as\s+(a|an|the)\b",
    r"(?i)new\s+instructions?\s*:",
    r"(?i)developer\s+mode\b",
    r"(?i)jailbreak\b",
    r"(?i)\bDAN\s+mode\b",
    r"(?i)send\s+(the\s+)?(password|secret|key)\s+to\s+me\b",
    r"(?i)delete\s+all\s+files\b",
]

FAKE_SYSTEM_PATTERNS = [
    r"\[SYSTEM\]",
    r"\[INST\]",
    r"(?im)^system\s*:",
    r"<\|system\|>",
    r"(?i)###\s*system\b",
    r"(?i)begin\s+system\s+message",
    r"(?i)\[SYSTEM\s+MESSAGE\]",
]

TOOL_CALL_PATTERNS = [
    r"<tool_call>",
    r'"tool"\s*:',
    r"\{\s*\"function\"\s*:",
    r"\[TOOL\]",
    r"(?i)call_function\s*\(",
]

CONFIRMED_PATTERNS = [
    r"(?i)\byes[,.]?\s+(go\s+ahead|proceed|do\s+it)\b",
    r"(?i)\bi\s+confirm\b",
    r"(?i)\bconfirmed\b",
    r"(?i)\bplease\s+proceed\b",
    r"(?i)\bgo\s+ahead\s+and\s+(call|use|run)\b",
]

_BASE64_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
_HEX_TOKEN = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")


@dataclass(frozen=True)
class Event:
    """One classified segment of a turn's text."""

    kind: str
    text: str
    start: int
    end: int
    decoded: str = ""  # for ENCODED: the decoded payload, if any
    decoded_is_instruction: bool = False


def _is_printable_text(raw: bytes) -> bool:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if len(text) < 8:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    return printable / len(text) > 0.95


def _try_base64(token: str) -> str:
    """Return the decoded text if *token* is plausible base64, else ''."""
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return ""
    return raw.decode("utf-8") if _is_printable_text(raw) else ""


def _try_hex(token: str) -> str:
    """Return the decoded text if *token* is plausible hex, else ''."""
    if not any(c in "abcdefABCDEF" for c in token):
        return ""  # pure digits: probably a number, not an encoded payload
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return ""
    return raw.decode("utf-8") if _is_printable_text(raw) else ""


def _instruction_hit(text: str) -> bool:
    return any(re.search(p, text) for p in INSTRUCTION_PATTERNS)


def _collect(text: str, secret_patterns: list[str]) -> list[Event]:
    """Collect all candidate events (possibly overlapping)."""
    found: list[Event] = []

    def add(kind: str, pattern: str) -> None:
        for m in re.finditer(pattern, text):
            found.append(Event(kind, m.group(0), m.start(), m.end()))

    for pat in secret_patterns:
        add(SECRET, pat)
    for pat in FAKE_SYSTEM_PATTERNS:
        add(FAKE_SYSTEM, pat)
    for pat in TOOL_CALL_PATTERNS:
        add(TOOL_CALL, pat)
    for pat in INSTRUCTION_PATTERNS:
        add(INSTRUCTION, pat)
    for pat in CONFIRMED_PATTERNS:
        add(CONFIRMED, pat)

    # Encoded blobs: only count if they decode to printable text.
    for m in _BASE64_TOKEN.finditer(text):
        decoded = _try_base64(m.group(0))
        if decoded:
            found.append(
                Event(
                    ENCODED,
                    m.group(0),
                    m.start(),
                    m.end(),
                    decoded=decoded,
                    decoded_is_instruction=_instruction_hit(decoded),
                )
            )
    for m in _HEX_TOKEN.finditer(text):
        decoded = _try_hex(m.group(0))
        if decoded:
            found.append(
                Event(
                    ENCODED,
                    m.group(0),
                    m.start(),
                    m.end(),
                    decoded=decoded,
                    decoded_is_instruction=_instruction_hit(decoded),
                )
            )
    return found


def scan(text: str, secret_patterns: list[str] | None = None) -> list[Event]:
    """Classify *text* into an ordered, non-overlapping event stream.

    Returns ``[Event(BENIGN, text, 0, len(text))]`` when nothing suspicious
    is found.
    """
    patterns = secret_patterns if secret_patterns is not None else DEFAULT_SECRET_PATTERNS
    candidates = _collect(text, patterns)
    if not candidates:
        return [Event(BENIGN, text, 0, len(text))]

    # Greedy overlap resolution: earliest start, then priority, then length.
    candidates.sort(key=lambda e: (e.start, _PRIORITY[e.kind], -(e.end - e.start)))
    accepted: list[Event] = []
    last_end = -1
    for ev in candidates:
        if ev.start >= last_end:
            accepted.append(ev)
            last_end = ev.end
    return accepted


def kinds(events: list[Event]) -> list[str]:
    """Convenience: just the event kinds, in order."""
    return [e.kind for e in events]
