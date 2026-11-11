"""Command line entry point: ``python -m aegis`` runs the demo,
``python -m aegis verify`` runs the verifier only.
"""

import sys

from .demo import run_demo
from .policy import DEFAULT_POLICY, WEAK_POLICY
from .verifier import verify, verify_automaton


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "verify":
        print(verify(DEFAULT_POLICY))
        print()
        print(verify(WEAK_POLICY))
        print()
        for check in verify_automaton(DEFAULT_POLICY, max_len=3):
            status = "PASS" if check.passed else "FAIL"
            print(
                f"  [{status}] {check.rule}: "
                f"{check.sequences_checked} sequences checked, "
                f"{len(check.violations)} violations"
            )
        return 0
    run_demo()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
