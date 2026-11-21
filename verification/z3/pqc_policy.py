"""Z3 proofs for the signature-aware policy (policy::evaluate_signed).

Run:  python verification/z3/pqc_policy.py
Exits non-zero if any property fails.
"""
import sys

from z3 import And, Bool, Not, Real, RealVal, Solver, sat, unsat

DENY_THRESHOLD = RealVal("7/10")  # keep in sync with policy::DENY_THRESHOLD

authenticated = Bool("authenticated")
authorized = Bool("authorized")
signature_valid = Bool("signature_valid")
risk_score = Real("risk_score")
access_allowed = Bool("access_allowed")

solver = Solver()
solver.add(risk_score >= 0, risk_score <= 1)
solver.add(
    access_allowed
    == And(authenticated, authorized, signature_valid, risk_score < DENY_THRESHOLD)
)


def expect(name, expected, *constraints):
    solver.push()
    solver.add(*constraints)
    result = solver.check()
    solver.pop()
    ok = result == expected
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {result}")
    return ok


results = [
    expect("unauthenticated is never allowed", unsat, Not(authenticated), access_allowed),
    expect("unauthorized is never allowed", unsat, Not(authorized), access_allowed),
    expect("an invalid signature is never allowed", unsat, Not(signature_valid), access_allowed),
    expect("risk >= 0.70 is never allowed", unsat, risk_score >= DENY_THRESHOLD, access_allowed),
    expect("all conditions met and low risk can be allowed",
           sat, authenticated, authorized, signature_valid, risk_score == RealVal("1/5"),
           access_allowed),
]

sys.exit(0 if all(results) else 1)
