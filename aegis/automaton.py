"""Finite-state automata and policy compilation.

Every policy rule compiles to a small deterministic finite automaton (DFA)
over the event alphabet produced by :mod:`aegis.scanner`.  A conversation
turn is *safe* with respect to a rule iff the DFA accepts its event stream.

The monitor runs the *product* of the applicable rule DFAs, so the combined
verdict is itself a single automaton check, while per-rule reporting re-runs
each rule DFA individually.  Because the automata are tiny and explicit, the
verifier (``verifier.py``) can exhaustively enumerate all short event
sequences and prove that no accepted sequence violates a safety property —
bounded exhaustive checking, not heuristic sampling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product as _cartesian

from . import scanner


@dataclass
class DFA:
    """A deterministic finite automaton over scanner event kinds."""

    name: str
    states: frozenset[str]
    alphabet: frozenset[str]
    transitions: dict[tuple[str, str], str]
    start: str
    accept: frozenset[str]

    def step(self, state: str, symbol: str) -> str:
        """One transition; unknown symbols leave the state unchanged."""
        return self.transitions.get((state, symbol), state)

    def run(self, symbols: list[str]) -> str:
        """Final state after consuming *symbols*."""
        state = self.start
        for sym in symbols:
            state = self.step(state, sym)
        return state

    def accepts(self, symbols: list[str]) -> bool:
        return self.run(symbols) in self.accept


def _trap_dfa(name: str, alphabet: frozenset[str], bad: str) -> DFA:
    """Two-state DFA: ``bad`` events move to a non-accepting trap state.

    Used for "never see event X" rules (secret output, instruction override,
    fake system markers, encoded payloads).
    """
    states = frozenset({"OK", "VIOLATED"})
    transitions: dict[tuple[str, str], str] = {}
    for sym in alphabet:
        transitions[("OK", sym)] = "VIOLATED" if sym == bad else "OK"
        transitions[("VIOLATED", sym)] = "VIOLATED"
    return DFA(name, states, alphabet, transitions, "OK", frozenset({"OK"}))


def never_output_secret_dfa() -> DFA:
    return _trap_dfa(
        "never-output-secret", frozenset(scanner.ALL_EVENTS), scanner.SECRET
    )


def no_instruction_override_dfa() -> DFA:
    return _trap_dfa(
        "no-instruction-override", frozenset(scanner.ALL_EVENTS), scanner.INSTRUCTION
    )


def no_fake_system_dfa() -> DFA:
    return _trap_dfa(
        "no-fake-system", frozenset(scanner.ALL_EVENTS), scanner.FAKE_SYSTEM
    )


def no_encoded_payload_dfa() -> DFA:
    return _trap_dfa(
        "no-encoded-payload", frozenset(scanner.ALL_EVENTS), scanner.ENCODED
    )


def tool_call_requires_intent_dfa() -> DFA:
    """A TOOL_CALL is accepted only after a CONFIRMED event in the same turn.

    States: START (no confirmation yet), CONFIRMED (intent established),
    VIOLATED (tool call without prior confirmation).
    """
    alphabet = frozenset(scanner.ALL_EVENTS)
    states = frozenset({"START", "CONFIRMED", "VIOLATED"})
    transitions: dict[tuple[str, str], str] = {}
    for sym in alphabet:
        transitions[("START", sym)] = (
            "VIOLATED" if sym == scanner.TOOL_CALL
            else "CONFIRMED" if sym == scanner.CONFIRMED
            else "START"
        )
        transitions[("CONFIRMED", sym)] = (
            "CONFIRMED" if sym in (scanner.CONFIRMED, scanner.TOOL_CALL) else "CONFIRMED"
        )
        transitions[("VIOLATED", sym)] = "VIOLATED"
    return DFA(
        "tool-call-requires-intent",
        states,
        alphabet,
        transitions,
        "START",
        frozenset({"START", "CONFIRMED"}),
    )


def product(*dfas: DFA, name: str = "product") -> DFA:
    """Synchronous product of DFAs: accepts iff every factor accepts."""
    if not dfas:
        raise ValueError("product needs at least one DFA")
    alphabet = frozenset().union(*(d.alphabet for d in dfas))
    state_lists = [sorted(d.states) for d in dfas]
    states = frozenset(
        "|".join(combo) for combo in _cartesian(*state_lists)
    )
    start = "|".join(d.start for d in dfas)
    accept = frozenset(
        "|".join(combo)
        for combo in _cartesian(*state_lists)
        if all(c in d.accept for c, d in zip(combo, dfas))
    )
    transitions: dict[tuple[str, str], str] = {}
    for combo in _cartesian(*state_lists):
        state = "|".join(combo)
        for sym in alphabet:
            nxt = "|".join(d.step(c, sym) for c, d in zip(combo, dfas))
            transitions[(state, sym)] = nxt
    return DFA(name, states, alphabet, transitions, start, accept)
