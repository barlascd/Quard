"""Z3 proofs that the access policy (src/policy.rs) behaves as intended.

Run:  python verification/z3/policy.py
Exits non-zero if any property fails (explicit checks, not `assert`,
so they still run under `python -O`).
"""
import sys

from z3 import And, Bool, Not, Real, RealVal, Solver, sat, unsat

DENY_THRESHOLD = RealVal("7/10")  # keep in sync with policy::DENY_THRESHOLD

authenticated = Bool("authenticated")
authorized = Bool("authorized")
risk = Real("risk")
allow = Bool("allow")

solver = Solver()
solver.add(risk >= 0, risk <= 1)
solver.add(allow == And(authenticated, authorized, risk < DENY_THRESHOLD))


def expect(name, expected, *constraints):
    solver.push()
    solver.add(*constraints)
    result = solver.check()
    solver.pop()
    ok = result == expected
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {result}")
    return ok


results = [
    expect("unauthenticated users are never allowed", unsat, Not(authenticated), allow),
    expect("unauthorized users are never allowed", unsat, Not(authorized), allow),
    expect("risk >= 0.70 is never allowed", unsat, risk >= DENY_THRESHOLD, allow),
    expect("a low-risk, authenticated, authorized user can be allowed",
           sat, authenticated, authorized, risk == RealVal("1/5"), allow),
]

sys.exit(0 if all(results) else 1)
