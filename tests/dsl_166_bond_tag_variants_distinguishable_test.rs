//! Requirement DSL-166: `BondTag::Reporter(h)` and `BondTag::Appellant(h)` are distinguishable across PartialEq, Hash, escrow-slot lookup, serde, and Copy.
//!
//! Traces to: docs/resources/SPEC.md §12.3.
//!
//! # Role
//!
//! `BondTag` uniquifies escrow slots via `(principal_idx, tag)`. The two variants wrap distinct hash domains:
//!
//!   - `Reporter(evidence_hash)` — locked by DSL-023 in `submit_evidence`.
//!   - `Appellant(appeal_hash)` — locked by DSL-062 in the appeal admission path.
//!
//! Although `evidence.hash()` and `appeal.hash()` use different domain prefixes (`DOMAIN_SLASHING_EVIDENCE` vs `DOMAIN_SLASH_APPEAL`) so cryptographic collision is implausible, the enum discriminant MUST still make `Reporter(h) != Appellant(h)` for any hypothetical shared `h`. Otherwise:
//!
//!   - A reporter could "inherit" an appellant bond slot by supplying the same Bytes32 inner value.
//!   - `BondEscrow::escrowed(idx, Appellant(h))` could leak reporter bond state.
//!   - Serde roundtrip on JSON snapshots could collapse the two variants.
//!
//! # Test matrix (maps to DSL-166 Test Plan)
//!
//!   1. `test_dsl_166_variants_not_equal` — `Reporter(h) != Appellant(h)` under PartialEq when `h` is identical.
//!   2. `test_dsl_166_hashes_differ` — Hash output differs between the two variants with identical inner bytes.
//!   3. `test_dsl_166_escrow_slots_separate` — BondEscrow: lock Reporter(h), query Appellant(h) → 0. Real-world interlock pinned.
//!   4. `test_dsl_166_serde_discriminator` — bincode + serde_json roundtrip each variant; post-decode equality AND cross-variant inequality.
//!   5. `test_dsl_166_copy_derive` — both variants `Copy` without moving; pattern-match after copy still compiles and matches.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher, RandomState};

use dig_protocol::Bytes32;
use dig_slashing::{BondError, BondEscrow, BondTag};

// ── mock BondEscrow — HashMap<(idx, tag), amount> ───────────────

struct MockBondEscrow {
    slots: HashMap<(u32, BondTag), u64>,
}

impl MockBondEscrow {
    fn new() -> Self {
        Self {
            slots: HashMap::new(),
        }
    }
}

impl BondEscrow for MockBondEscrow {
    fn lock(&mut self, idx: u32, amount: u64, tag: BondTag) -> Result<(), BondError> {
        if self.slots.contains_key(&(idx, tag)) {
            return Err(BondError::DoubleLock { tag });
        }
        self.slots.insert((idx, tag), amount);
        Ok(())
    }
    fn release(&mut self, idx: u32, _amount: u64, tag: BondTag) -> Result<(), BondError> {
        self.slots
            .remove(&(idx, tag))
            .ok_or(BondError::TagNotFound { tag })?;
        Ok(())
    }
    fn forfeit(&mut self, idx: u32, _amount: u64, tag: BondTag) -> Result<u64, BondError> {
        self.slots
            .remove(&(idx, tag))
            .ok_or(BondError::TagNotFound { tag })
    }
    fn escrowed(&self, idx: u32, tag: BondTag) -> u64 {
        self.slots.get(&(idx, tag)).copied().unwrap_or(0)
    }
}

// ── tests ──────────────────────────────────────────────────────

/// DSL-166 row 1: variants with identical inner `Bytes32` are NOT
/// PartialEq-equal.
///
/// The enum discriminant — not the inner bytes — decides equality.
/// Pinning this rules out a future refactor to `struct BondTag { kind:
/// TagKind, hash: Bytes32 }` that might accidentally equate instances
/// by hash alone.
#[test]
fn test_dsl_166_variants_not_equal() {
    let h = Bytes32::new([0xAAu8; 32]);

    let reporter = BondTag::Reporter(h);
    let appellant = BondTag::Appellant(h);

    assert_ne!(
        reporter, appellant,
        "variants must differ via PartialEq even with identical inner h",
    );

    // Cross-check: identical variants with identical inner bytes ARE equal.
    assert_eq!(reporter, BondTag::Reporter(h));
    assert_eq!(appellant, BondTag::Appellant(h));

    // Identical variants with DIFFERENT inner bytes ARE not equal.
    let other_h = Bytes32::new([0xBBu8; 32]);
    assert_ne!(reporter, BondTag::Reporter(other_h));
}

/// DSL-166 row 2: Hash output differs between the two variants.
///
/// `HashMap<(u32, BondTag), u64>` uses std's hasher — if the variant
/// discriminant did not contribute to the hash, the two variants with
/// identical inner bytes would collide and the escrow map would
/// conflate them. Probe the raw hasher output to pin the
/// contribution.
///
/// Uses `RandomState` → fresh `BuildHasher::hasher()` per value so
/// the computation is deterministic within this test run.
#[test]
fn test_dsl_166_hashes_differ() {
    let h = Bytes32::new([0xCCu8; 32]);
    let reporter = BondTag::Reporter(h);
    let appellant = BondTag::Appellant(h);

    // Build both hashers from the SAME state so any difference is
    // attributable to the value, not the hasher seed.
    let state = RandomState::new();
    let mut h_reporter = state.build_hasher();
    let mut h_appellant = state.build_hasher();
    std::hash::Hash::hash(&reporter, &mut h_reporter);
    std::hash::Hash::hash(&appellant, &mut h_appellant);

    assert_ne!(
        h_reporter.finish(),
        h_appellant.finish(),
        "Hash output must differ between variants with identical inner bytes \
         — otherwise HashMap<(idx, BondTag), _> collapses the two slots",
    );
}

/// DSL-166 row 3: real escrow-slot separation — lock Reporter, query
/// Appellant returns 0.
///
/// Pins the end-to-end interlock in a HashMap-backed BondEscrow
/// (the canonical consumer-side impl). This is the observable
/// consequence of rows 1 + 2: if PartialEq or Hash drifted, this
/// test would surface the bug as a non-zero `escrowed(Appellant)`.
#[test]
fn test_dsl_166_escrow_slots_separate() {
    let mut escrow = MockBondEscrow::new();
    let h = Bytes32::new([0xDDu8; 32]);
    let amount = 500_000_000;

    escrow
        .lock(42, amount, BondTag::Reporter(h))
        .expect("lock reporter slot");

    assert_eq!(
        escrow.escrowed(42, BondTag::Reporter(h)),
        amount,
        "Reporter slot carries the locked amount",
    );
    assert_eq!(
        escrow.escrowed(42, BondTag::Appellant(h)),
        0,
        "Appellant slot with same h must be empty — slots are disjoint",
    );

    // Locking the Appellant slot afterwards does NOT DoubleLock the
    // Reporter slot — they're keyed distinctly.
    escrow
        .lock(42, amount * 2, BondTag::Appellant(h))
        .expect("lock appellant slot independently");
    assert_eq!(escrow.escrowed(42, BondTag::Reporter(h)), amount);
    assert_eq!(escrow.escrowed(42, BondTag::Appellant(h)), amount * 2);

    // And DoubleLock fires per-slot — re-locking Reporter(h) for
    // the same idx is rejected.
    let err = escrow.lock(42, amount, BondTag::Reporter(h)).unwrap_err();
    assert!(matches!(err, BondError::DoubleLock { .. }));
}

/// DSL-166 row 4: serde discriminator preserved.
///
/// bincode encodes `enum` variants as `u32` tag + inner data.
/// serde_json uses an externally-tagged object. Both must roundtrip
/// each variant distinctly — a bug that collapses Reporter ↔
/// Appellant would surface as post-decode equality between the two.
#[test]
fn test_dsl_166_serde_discriminator() {
    let h = Bytes32::new([0xEEu8; 32]);
    let reporter = BondTag::Reporter(h);
    let appellant = BondTag::Appellant(h);

    // bincode roundtrip — each variant preserves its discriminant.
    let bin_r = bincode::serialize(&reporter).expect("bincode ser reporter");
    let bin_a = bincode::serialize(&appellant).expect("bincode ser appellant");
    assert_ne!(
        bin_r, bin_a,
        "bincode wire for Reporter != Appellant (discriminant differs)",
    );
    let dec_r: BondTag = bincode::deserialize(&bin_r).expect("bincode deser r");
    let dec_a: BondTag = bincode::deserialize(&bin_a).expect("bincode deser a");
    assert_eq!(dec_r, reporter);
    assert_eq!(dec_a, appellant);
    assert_ne!(dec_r, dec_a, "post-decode variants remain distinguishable",);

    // serde_json roundtrip — same invariants.
    let json_r = serde_json::to_string(&reporter).expect("json ser r");
    let json_a = serde_json::to_string(&appellant).expect("json ser a");
    assert_ne!(json_r, json_a, "JSON strings differ between variants");
    // Variant name should appear literally in the JSON form.
    assert!(
        json_r.contains("Reporter"),
        "JSON carries Reporter tag: {json_r}",
    );
    assert!(
        json_a.contains("Appellant"),
        "JSON carries Appellant tag: {json_a}",
    );
    let json_dec_r: BondTag = serde_json::from_str(&json_r).expect("json deser r");
    let json_dec_a: BondTag = serde_json::from_str(&json_a).expect("json deser a");
    assert_eq!(json_dec_r, reporter);
    assert_eq!(json_dec_a, appellant);
    assert_ne!(json_dec_r, json_dec_a);
}

/// DSL-166 row 5: Copy derive works for both variants.
///
/// `BondTag` carries `#[derive(Copy)]` so it passes by value without
/// move semantics — callers like `BondEscrow::lock(idx, amount, tag)`
/// can take ownership of the tag without cloning. Pin this property
/// by explicitly copying each variant through a function argument +
/// binding-after-move continuation.
#[test]
fn test_dsl_166_copy_derive() {
    fn takes_by_value(tag: BondTag) -> BondTag {
        tag
    }

    let h = Bytes32::new([0xF0u8; 32]);
    let reporter = BondTag::Reporter(h);
    let appellant = BondTag::Appellant(h);

    // If Copy were missing, these lines would each produce a move
    // and the subsequent use of `reporter` / `appellant` would
    // fail to compile.
    let _copy_r = takes_by_value(reporter);
    let _copy_a = takes_by_value(appellant);

    // Originals still usable post-copy.
    assert!(matches!(reporter, BondTag::Reporter(_)));
    assert!(matches!(appellant, BondTag::Appellant(_)));

    // Pattern match after Copy propagates the inner value verbatim.
    match reporter {
        BondTag::Reporter(inner) => assert_eq!(inner, h),
        BondTag::Appellant(_) => panic!("variant drift after Copy"),
    }
}
