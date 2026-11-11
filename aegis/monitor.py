"""Runtime monitor: checks a conversation against a compiled policy.

The monitor feeds each turn's scanned event stream through the policy's
automata and reports, per rule, whether the guarantee held or failed.
It also performs one check that no single-turn automaton can express:
multi-turn smuggling, where an instruction is split across consecutive
user turns so that no single turn matches an instruction pattern, but the
concatenated text does.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field

from . import scanner
from .policy import Policy
from .scanner import Event


@dataclass(frozen=True)
class Turn:
    role: str  # "system" | "user" | "assistant" | "tool"
    text: str


@dataclass(frozen=True)
class Violation:
    rule: str
    detail: str
    turn_index: int
    action: str  # "BLOCK" | "QUARANTINE"


@dataclass
class Verdict:
    allowed: bool
    action: str  # "ALLOW" | "BLOCK" | "QUARANTINE"
    violations: list[Violation] = field(default_factory=list)
    # rule name -> "held" | "FAILED"
    per_rule: dict[str, str] = field(default_factory=dict)

    def failed_rules(self) -> list[str]:
        return [name for name, state in self.per_rule.items() if state == "FAILED"]


# Multi-turn smuggling is checked over the last N user turns.
SMUGGLE_WINDOW = 3


class Monitor:
    """Stateful monitor for one conversation (or one request)."""

    def __init__(self, policy: Policy):
        self.policy = policy
        self._user_product = policy.compile_user_product()
        self._user_rule_dfas = {r.name: r.dfa() for r in policy.user_rules()}
        self._assistant_rule_dfas = {
            r.name: r.dfa() for r in policy.assistant_rules()
        }
        self._recent_user_texts: deque[str] = deque(maxlen=SMUGGLE_WINDOW)

    # -- public API ---------------------------------------------------------

    def check(self, turns: list[Turn]) -> Verdict:
        """Check a whole conversation; returns the aggregate verdict."""
        violations: list[Violation] = []
        per_rule: dict[str, str] = {r.name: "held" for r in self.policy.rules}
        self._recent_user_texts.clear()
        confirmed_pending = False  # user confirmation licensing the next tool call

        for idx, turn in enumerate(turns):
            if turn.role == "system":
                continue  # trusted; nothing to check
            events = scanner.scan(turn.text, self.policy.secret_patterns)
            kinds = scanner.kinds(events)

            if turn.role == "user":
                # A confirmation in this turn licenses a tool call in the
                # immediately following assistant turn (and only that one).
                confirmed_pending = scanner.CONFIRMED in kinds
                violations += self._check_user_turn(idx, turn, events, kinds, per_rule)
            elif turn.role == "assistant":
                violations += self._check_assistant_turn(
                    idx, events, kinds, per_rule, confirmed_pending
                )
                confirmed_pending = False
            # "tool" turns carry tool *results*; they are data, not commands.

        if not violations:
            return Verdict(True, "ALLOW", [], per_rule)
        action = "BLOCK" if any(v.action == "BLOCK" for v in violations) else "QUARANTINE"
        return Verdict(False, action, violations, per_rule)

    def check_text(self, role: str, text: str) -> Verdict:
        """Convenience: check a single turn."""
        return self.check([Turn(role, text)])

    # -- per-turn checks ----------------------------------------------------

    def _check_user_turn(
        self,
        idx: int,
        turn: Turn,
        events: list[Event],
        kinds: list[str],
        per_rule: dict[str, str],
    ) -> list[Violation]:
        violations: list[Violation] = []

        # Combined product check (single automaton verdict).
        if not self._user_product.accepts(kinds):
            # Re-run each rule DFA to attribute the failure precisely.
            for name, dfa in self._user_rule_dfas.items():
                if not dfa.accepts(kinds):
                    rule = self.policy.rule_by_name(name)
                    per_rule[name] = "FAILED"
                    detail = self._detail_for(name, events)
                    violations.append(Violation(name, detail, idx, rule.action))

        # Multi-turn smuggling: instruction split across consecutive turns.
        self._recent_user_texts.append(turn.text)
        if self._smuggled_instruction():
            per_rule["no-instruction-override"] = "FAILED"
            violations.append(
                Violation(
                    "no-instruction-override",
                    "instruction split across consecutive user turns "
                    "(matches only when turns are concatenated)",
                    idx,
                    "BLOCK",
                )
            )
        return violations

    def _check_assistant_turn(
        self,
        idx: int,
        events: list[Event],
        kinds: list[str],
        per_rule: dict[str, str],
        confirmed_pending: bool = False,
    ) -> list[Violation]:
        violations: list[Violation] = []
        for name, dfa in self._assistant_rule_dfas.items():
            # The tool-call rule sees a synthetic CONFIRMED at the head of
            # the stream when the user confirmed in the previous turn.
            run_kinds = (
                [scanner.CONFIRMED] + kinds
                if name == "tool-call-requires-intent" and confirmed_pending
                else kinds
            )
            if not dfa.accepts(run_kinds):
                rule = self.policy.rule_by_name(name)
                per_rule[name] = "FAILED"
                violations.append(
                    Violation(name, self._detail_for(name, events), idx, rule.action)
                )
        return violations

    # -- helpers ------------------------------------------------------------

    def _smuggled_instruction(self) -> bool:
        """True if the recent user turns jointly form an instruction that no
        single turn contains.  Returns False when any single turn already
        matches (that case is caught by the per-turn automaton)."""
        texts = list(self._recent_user_texts)
        if len(texts) < 2:
            return False
        if any(scanner._instruction_hit(t) for t in texts):
            return False
        joined = " ".join(texts)
        return scanner._instruction_hit(joined)

    @staticmethod
    def _detail_for(rule_name: str, events: list[Event]) -> str:
        # Only report events that are relevant to the rule being detailed.
        wanted = {
            "never-output-secret": scanner.SECRET,
            "no-instruction-override": scanner.INSTRUCTION,
            "no-fake-system": scanner.FAKE_SYSTEM,
            "no-encoded-payload": scanner.ENCODED,
            "tool-call-requires-intent": scanner.TOOL_CALL,
        }.get(rule_name)
        for ev in events:
            if ev.kind != wanted:
                continue
            if ev.kind == scanner.SECRET:
                return f"secret pattern matched: {ev.text[:40]!r}"
            if ev.kind == scanner.INSTRUCTION:
                return f"instruction phrase: {ev.text[:60]!r}"
            if ev.kind == scanner.FAKE_SYSTEM:
                return f"fake system marker: {ev.text[:40]!r}"
            if ev.kind == scanner.ENCODED:
                suffix = (
                    f" (decodes to an instruction: {ev.decoded[:60]!r})"
                    if ev.decoded_is_instruction
                    else f" (decodes to: {ev.decoded[:60]!r})"
                )
                return f"encoded blob {ev.text[:40]!r}{suffix}"
            if ev.kind == scanner.TOOL_CALL:
                return "tool call without a prior user confirmation in this turn"
        return "rule violated"
