---------------------------- MODULE system ----------------------------
(* Mirrors src/isolation.rs. Check with TLC using system.cfg. *)
EXTENDS Naturals

CONSTANT MaxRisk          \* risk at or above this is "high risk"
VARIABLES state, risk, recoveryApproved

vars == <<state, risk, recoveryApproved>>

States == {"Normal", "Restricted", "Isolated", "Recovery"}

TypeOK ==
    /\ state \in States
    /\ risk \in 0..(MaxRisk + 1)
    /\ recoveryApproved \in BOOLEAN

Init ==
    /\ state = "Normal"
    /\ risk = 0
    /\ recoveryApproved = FALSE

\* The environment changes the observed risk and the approval flag.
Environment ==
    /\ risk' \in 0..(MaxRisk + 1)
    /\ recoveryApproved' \in BOOLEAN
    /\ UNCHANGED state

Escalate ==
    /\ state \in {"Normal", "Restricted"}
    /\ risk >= MaxRisk
    /\ state' = IF state = "Normal" THEN "Restricted" ELSE "Isolated"
    /\ UNCHANGED <<risk, recoveryApproved>>

StartRecovery ==
    /\ state = "Isolated"
    /\ recoveryApproved
    /\ state' = "Recovery"
    /\ UNCHANGED <<risk, recoveryApproved>>

FinishRecovery ==
    /\ state = "Recovery"
    /\ recoveryApproved
    /\ state' = "Normal"
    /\ UNCHANGED <<risk, recoveryApproved>>

FailRecovery ==
    /\ state = "Recovery"
    /\ ~recoveryApproved
    /\ state' = "Isolated"
    /\ UNCHANGED <<risk, recoveryApproved>>

Next == Environment \/ Escalate \/ StartRecovery \/ FinishRecovery \/ FailRecovery

Spec == Init /\ [][Next]_vars

\* Safety: Normal never jumps straight to Isolated or Recovery.
NoSkipFromNormal ==
    [][state = "Normal" => state' \in {"Normal", "Restricted"}]_vars

\* Safety: leaving Isolated is only possible with an approval.
RecoveryNeedsApproval ==
    [][(state = "Isolated" /\ state' # "Isolated") => recoveryApproved]_vars
=======================================================================
