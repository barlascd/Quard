-- Check with:  lean verification/lean/Theorem.lean
def canAccess (authenticated authorized : Bool) : Bool :=
  authenticated && authorized

theorem unauthenticated_cannot_access (authorized : Bool) :
    canAccess false authorized = false := by
  simp [canAccess]

theorem unauthorized_cannot_access (authenticated : Bool) :
    canAccess authenticated false = false := by
  simp [canAccess]
