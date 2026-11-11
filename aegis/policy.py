"""Policy DSL: human-readable rules compiled to automata.

A policy is a named list of rules.  Each rule declares:

* ``name`` / ``description`` — what guarantee it states,
* ``applies_to`` — which turn roles it constrains: ``"user"`` (untrusted
  input), ``"assistant"`` (model output), or ``"both"``,
* ``dfa`` — a factory producing the rule's automaton (see ``automaton.py``),
* ``action`` — what the monitor does on violation: ``"BLOCK"`` or
  ``"QUARANTINE"`` (flag for review instead of hard-blocking).

``Policy.compile()`` returns the product automaton for the user-scope rules
plus the individual rule DFAs used for per-rule reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import automaton, scanner


@dataclass(frozen=True)
class Rule:
    name: str
    description: str
    applies_to: str  # "user" | "assistant" | "both"
    action: str  # "BLOCK" | "QUARANTINE"
    dfa_factory: object  # callable[[], automaton.DFA]

    def dfa(self) -> automaton.DFA:
        return self.dfa_factory()  # type: ignore[operator]


# -- Rule definitions -------------------------------------------------------

NEVER_OUTPUT_SECRET = Rule(
    name="never-output-secret",
    description="Model output must never contain text matching a secret pattern.",
    applies_to="assistant",
    action="BLOCK",
    dfa_factory=automaton.never_output_secret_dfa,
)

NO_INSTRUCTION_OVERRIDE = Rule(
    name="no-instruction-override",
    description="Instruction-like phrases in user content are untrusted data, "
    "never commands to follow.",
    applies_to="user",
    action="BLOCK",
    dfa_factory=automaton.no_instruction_override_dfa,
)

NO_FAKE_SYSTEM = Rule(
    name="no-fake-system",
    description="Fake system-role markers in user content are rejected.",
    applies_to="user",
    action="BLOCK",
    dfa_factory=automaton.no_fake_system_dfa,
)

NO_ENCODED_PAYLOAD = Rule(
    name="no-encoded-payload",
    description="Base64/hex blobs that decode to text are quarantined: "
    "encoding must not smuggle instructions past the filter.",
    applies_to="user",
    action="QUARANTINE",
    dfa_factory=automaton.no_encoded_payload_dfa,
)

TOOL_CALL_REQUIRES_INTENT = Rule(
    name="tool-call-requires-intent",
    description="A tool call is allowed only after an explicit user "
    "confirmation (in the same turn's event stream, or in the immediately "
    "preceding user turn, which the monitor carries forward).",
    applies_to="assistant",
    action="BLOCK",
    dfa_factory=automaton.tool_call_requires_intent_dfa,
)


@dataclass
class Policy:
    """A named set of rules plus the secret patterns the scanner uses."""

    name: str
    rules: list[Rule]
    secret_patterns: list[str] = field(
        default_factory=lambda: list(scanner.DEFAULT_SECRET_PATTERNS)
    )

    def user_rules(self) -> list[Rule]:
        return [r for r in self.rules if r.applies_to in ("user", "both")]

    def assistant_rules(self) -> list[Rule]:
        return [r for r in self.rules if r.applies_to in ("assistant", "both")]

    def compile_user_product(self) -> automaton.DFA:
        """Product automaton over all user-scope rules (single combined check)."""
        dfas = [r.dfa() for r in self.user_rules()]
        if not dfas:
            raise ValueError("policy has no user-scope rules")
        return automaton.product(*dfas, name=f"{self.name}:user-product")

    def rule_by_name(self, name: str) -> Rule:
        for rule in self.rules:
            if rule.name == name:
                return rule
        raise KeyError(name)


DEFAULT_POLICY = Policy(
    name="default",
    rules=[
        NO_INSTRUCTION_OVERRIDE,
        NO_FAKE_SYSTEM,
        NO_ENCODED_PAYLOAD,
        NEVER_OUTPUT_SECRET,
        TOOL_CALL_REQUIRES_INTENT,
    ],
)

# Deliberately weak: identical to default but without the encoded-payload rule.
# The verifier uses it to demonstrate that a missing rule is *found* by
# exhaustive checking (counterexamples in the `encoded` attack class).
WEAK_POLICY = Policy(
    name="weak-no-encoded-rule",
    rules=[
        NO_INSTRUCTION_OVERRIDE,
        NO_FAKE_SYSTEM,
        NEVER_OUTPUT_SECRET,
        TOOL_CALL_REQUIRES_INTENT,
    ],
)
