"""Aegis: a prompt firewall with formally checked guarantees.

Policies compile to finite-state automata; a runtime monitor checks
prompts and responses against them; a verifier exhaustively checks the
automata against a bounded attack suite and all short event sequences.
"""

from .monitor import Monitor, Turn, Verdict, Violation
from .policy import DEFAULT_POLICY, WEAK_POLICY, Policy, Rule
from .verifier import VerificationReport, verify, verify_automaton

__all__ = [
    "Monitor",
    "Turn",
    "Verdict",
    "Violation",
    "Policy",
    "Rule",
    "DEFAULT_POLICY",
    "WEAK_POLICY",
    "VerificationReport",
    "verify",
    "verify_automaton",
]

__version__ = "0.1.0"
