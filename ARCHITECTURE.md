# Aegis architecture

## Data flow

```
user / assistant turn (text)
        │
        ▼
scanner.scan()            ──► ordered Event stream
        │                      (SECRET, INSTRUCTION, FAKE_SYSTEM,
        │                       ENCODED, TOOL_CALL, CONFIRMED, BENIGN)
        ▼
monitor.check()
   ├─ user turns:    product DFA of user-scope rules
   │                  + multi-turn smuggling check (rolling 3-turn window)
   ├─ assistant turns: secret DFA + tool-call DFA
   │                  (tool-call DFA sees a synthetic CONFIRMED when the
   │                   user confirmed in the immediately preceding turn)
   └─ system turns:  trusted, skipped
        │
        ▼
Verdict(allowed, action ∈ {ALLOW, BLOCK, QUARANTINE},
        violations, per-rule held/FAILED map)
```

## Components

### scanner.py — deterministic event classifier

- Pure functions over text: compiled regex libraries for secrets,
  instruction phrases, fake system markers, tool-call markers, and
  confirmation phrases.
- Encoded blobs: a base64/hex-looking token counts as `ENCODED` only if it
  decodes to printable UTF-8 text of length ≥ 8. The decoded payload is
  kept on the event, and flagged if it itself contains an instruction
  phrase. This avoids flagging ordinary long words or numbers.
- Overlap resolution is greedy and total: earliest start, then kind
  priority (SECRET > FAKE_SYSTEM > TOOL_CALL > INSTRUCTION > ENCODED >
  CONFIRMED), then longest match. Scanning is therefore deterministic.

### automaton.py — DFAs and the product construction

- `DFA` is a small explicit-state machine with `step` / `run` / `accepts`.
- Each rule compiles to a DFA:
  - "never see event X" rules are two-state trap DFAs (OK / VIOLATED).
  - `tool_call_requires_intent_dfa` is a three-state DFA
    (START / CONFIRMED / VIOLATED): a TOOL_CALL before CONFIRMED violates.
- `product(*dfas)` builds the synchronous product: it accepts iff every
  factor accepts. The monitor uses the product for the combined user-turn
  verdict and the individual DFAs for attribution.

### policy.py — the policy DSL

A `Policy` is a name, a list of `Rule`s (name, description, scope,
action, DFA factory), and the secret patterns the scanner uses.
`DEFAULT_POLICY` has five rules; `WEAK_POLICY` drops the encoded-payload
rule and exists so the verifier can demonstrate finding a hole.

### monitor.py — runtime monitor

- Stateful per conversation: it keeps a rolling window of the last 3 user
  turns for the smuggling check.
- **Multi-turn smuggling** cannot be expressed by a single-turn DFA, so
  it is a monitor-level check: if the concatenation of recent user turns
  matches an instruction pattern while no single turn does, the turn is
  blocked. (If a single turn already matches, the per-turn automaton has
  already fired, so the check does not double-count.)
- **Cross-turn confirmation**: a CONFIRMED event in a user turn licenses a
  tool call in the immediately following assistant turn only; the monitor
  injects a synthetic CONFIRMED at the head of that turn's stream for the
  tool-call DFA.
- Verdict actions: `ALLOW` (no violations), `BLOCK` (any BLOCK violation),
  `QUARANTINE` (only encoded-payload violations).

### verifier.py — two exhaustive bounded checks

1. **Attack-suite verification.** `generate_attacks()` enumerates 58
   attacks deterministically: 24 instruction overrides (6 templates × 4
   actions), 20 fake-system messages (5 templates × 4 actions), 6 encoded
   payloads (3 payloads × base64/hex), 8 multi-turn splits (one instruction
   split at every word boundary). Each is run through the real monitor; a
   class passes only if every attack is blocked, and passing attacks are
   returned as counterexamples.
2. **Automaton property verification.** For each rule, enumerate all event
   sequences up to length 3 over the 7-symbol alphabet (400 sequences) and
   check the rule's safety property on every sequence the DFA accepts:
   "no accepted sequence contains SECRET / INSTRUCTION / FAKE_SYSTEM /
   ENCODED", and "no accepted sequence has TOOL_CALL before CONFIRMED".

## What "formally checked" means here — and what it does not

The guarantee is precisely: *within the bounded attack suite and within
event sequences of length ≤ 3, no violation is possible.* That is a real,
checkable claim, and the verifier is strong enough to catch a missing rule
(see the weak-policy demo). It is **not** a claim that no attack exists:
the scanner's pattern library is finite, paraphrases outside it are not
covered, and the bound is finite.

**Production upgrade path:** replace the bounded enumeration with an SMT
solver (Z3). The DFAs are already explicit state machines, so the same
safety properties can be discharged as reachability queries over the
unbounded automaton: "is the VIOLATED state reachable from the start state
under any input sequence?" The scanner would additionally gain an
embedding-based classifier for paraphrase, with the DFA layer kept as the
verifiable core.
