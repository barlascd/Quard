#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemState {
    Normal,
    Restricted,
    Isolated,
    Recovery,
}

/// State machine that mirrors `verification/tla/system.tla`.
pub fn transition(
    current: SystemState,
    high_risk: bool,
    approved_recovery: bool,
) -> SystemState {
    use SystemState::*;
    match current {
        Normal if high_risk => Restricted,
        Normal => Normal,
        Restricted if high_risk => Isolated,
        Restricted => Restricted,
        Isolated if approved_recovery => Recovery,
        Isolated => Isolated,
        Recovery if approved_recovery => Normal,
        Recovery => Isolated,
    }
}
