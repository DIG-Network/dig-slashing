//! Requirement DSL-115: `enforce_slash_appeal_window_policy`
//! rejects appeals filed past the window
//! `submitted_at + SLASH_APPEAL_WINDOW_EPOCHS` via
//! `SlashingError::AppealWindowExpired`.
//!
//! Traces to: docs/resources/SPEC.md §16.2, §22.13.
//!
//! # Role
//!
//! Mempool pre-filter upstream of DSL-056 manager window check.
//! Same boundary semantics: inclusive on both ends, strict `>`
//! rejects. Reuses the existing `SlashingError::AppealWindowExpired`
//! variant so mempool and manager emit identical diagnostic
//! shapes.
//!
//! # Test matrix (maps to DSL-115 Test Plan + acceptance)
//!
//!   1. `test_dsl_115_past_window_rejected` — submitted=0,
//!      filed=WINDOW+1 → AppealWindowExpired with all three
//!      fields populated
//!   2. `test_dsl_115_boundary_ok` — filed == submitted + WINDOW
//!      admits (strict `>` excludes equality)
//!   3. `test_dsl_115_within_ok` — filed = submitted + 1 admits
//!   4. `test_dsl_115_unknown_hash_skipped` — appeal whose hash
//!      is not in the `submitted_at` map is out of scope for
//!      this check (DSL-114 handles it); must admit here
//!   5. `test_dsl_115_first_expired_short_circuits` — mixed
//!      batch halts at the first expired appeal

use std::collections::HashMap;

use dig_protocol::Bytes32;
use dig_slashing::{
    ProposerAppealGround, ProposerSlashingAppeal, SLASH_APPEAL_WINDOW_EPOCHS, SlashAppeal,
    SlashAppealPayload, SlashingError, enforce_slash_appeal_window_policy,
};

fn appeal_for(evidence_hash: Bytes32, filed_epoch: u64) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index: 11,
        appellant_puzzle_hash: Bytes32::new([0xAAu8; 32]),
        filed_epoch,
        payload: SlashAppealPayload::Proposer(ProposerSlashingAppeal {
            ground: ProposerAppealGround::HeadersIdentical,
            witness: vec![],
        }),
    }
}

/// DSL-115 row 1: past-window rejects with all three fields set.
#[test]
fn test_dsl_115_past_window_rejected() {
    let h = Bytes32::new([0x11u8; 32]);
    let submitted = 0u64;
    let filed = SLASH_APPEAL_WINDOW_EPOCHS + 1;

    let mut map = HashMap::new();
    map.insert(h, submitted);

    let ap = appeal_for(h, filed);
    let err = enforce_slash_appeal_window_policy(&[ap], &map).expect_err("past-window rejects");

    let SlashingError::AppealWindowExpired {
        submitted_at,
        window,
        current,
    } = err
    else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(submitted_at, submitted);
    assert_eq!(window, SLASH_APPEAL_WINDOW_EPOCHS);
    assert_eq!(current, filed);
}

/// DSL-115 row 2: boundary (strict `>` means `==` admits).
#[test]
fn test_dsl_115_boundary_ok() {
    let h = Bytes32::new([0x22u8; 32]);
    let submitted = 5u64;
    let filed = submitted + SLASH_APPEAL_WINDOW_EPOCHS;

    let mut map = HashMap::new();
    map.insert(h, submitted);

    let ap = appeal_for(h, filed);
    enforce_slash_appeal_window_policy(&[ap], &map)
        .expect("filed == submitted + WINDOW must admit (strict `>`)");
}

/// DSL-115 row 3: well inside the window.
#[test]
fn test_dsl_115_within_ok() {
    let h = Bytes32::new([0x33u8; 32]);
    let submitted = 5u64;
    let filed = submitted + 1;

    let mut map = HashMap::new();
    map.insert(h, submitted);

    let ap = appeal_for(h, filed);
    enforce_slash_appeal_window_policy(&[ap], &map).expect("in-window admits");
}

/// Edge: appeal whose evidence_hash is not in the submitted_at
/// map is NOT rejected here. Responsibility separation with
/// DSL-114: unknown-hash goes through that policy; window goes
/// through this one.
#[test]
fn test_dsl_115_unknown_hash_skipped() {
    let known = Bytes32::new([0x44u8; 32]);
    let unknown = Bytes32::new([0x55u8; 32]);
    let mut map = HashMap::new();
    map.insert(known, 0u64);

    // Even filed way past any conceivable window — skipped because
    // the map has no entry for this hash.
    let ap = appeal_for(unknown, 999_999);
    enforce_slash_appeal_window_policy(&[ap], &map)
        .expect("unknown-hash appeal is out of scope here");
}

/// Bonus: short-circuit on first expired entry in mixed batch.
/// The error must carry the FIRST expired appeal's submitted_at
/// and filed_epoch, not a later entry's.
#[test]
fn test_dsl_115_first_expired_short_circuits() {
    let h_first = Bytes32::new([0xAAu8; 32]);
    let h_ok = Bytes32::new([0xBBu8; 32]);
    let h_later = Bytes32::new([0xCCu8; 32]);

    let mut map = HashMap::new();
    map.insert(h_first, 0u64);
    map.insert(h_ok, 100u64);
    map.insert(h_later, 0u64);

    let appeals = vec![
        appeal_for(h_first, SLASH_APPEAL_WINDOW_EPOCHS + 1), // expired
        appeal_for(h_ok, 100),                               // in-window
        appeal_for(h_later, SLASH_APPEAL_WINDOW_EPOCHS + 500), // also expired
    ];
    let err = enforce_slash_appeal_window_policy(&appeals, &map).unwrap_err();

    let SlashingError::AppealWindowExpired {
        submitted_at,
        current,
        ..
    } = err
    else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(submitted_at, 0);
    assert_eq!(
        current,
        SLASH_APPEAL_WINDOW_EPOCHS + 1,
        "carries FIRST expired appeal's filed_epoch, not the later one",
    );
}
