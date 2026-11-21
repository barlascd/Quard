// Check with:  verus --crate-type=lib verification/verus/score.rs
use vstd::prelude::*;

verus! {

pub open spec fn valid_score(score: int) -> bool {
    0 <= score && score <= 100
}

pub fn clamp_score(score: u64) -> (result: u64)
    ensures
        result <= 100,
        valid_score(result as int),
{
    if score > 100 {
        100
    } else {
        score
    }
}

} // verus!
