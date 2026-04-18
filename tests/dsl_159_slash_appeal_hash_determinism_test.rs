//! Requirement DSL-159: `SlashAppeal::hash()` is deterministic
//! content-address over `DOMAIN_SLASH_APPEAL || bincode(self)`.
//!
//! Traces to: docs/resources/SPEC.md §3.7, §2.10.
//!
//! # Role
//!
//! `SlashAppeal::hash()` identifies an appeal across the system:
//!
//!   - DSL-058 `pending.appeal_history` dedup key.
//!   - DSL-070 / DSL-072 `AppealAttempt::appeal_hash` recording
//!     (winning appeal identity for later revert replay).
//!   - DSL-057 adjudication routing — the adjudicator indexes by
//!     appeal hash when resolving the winning attempt.
//!
//! Two properties are load-bearing:
//!
//!   1. **Determinism** — calling `hash()` twice on the same
//!      envelope yields the same Bytes32. Runs of the same binary
//!      on different machines also agree (bincode canonical
//!      encoding + domain-tagged SHA-256).
//!   2. **Sensitivity** — every field materially contributes to
//!      the digest; any one-bit mutation shifts the output. This
//!      is the collision-resistance property that makes the hash
//!      usable as a dedup key.
//!
//! Domain-tagged prefix `DOMAIN_SLASH_APPEAL = b"DIG_SLASH_APPEAL_V1"`
//! keeps appeal digests disjoint from evidence digests (DSL-002
//! uses `DOMAIN_SLASHING_EVIDENCE`). This prevents a
//! byte-identical appeal + evidence pair from colliding in the
//! pending-book / appeal-history cross-lookups.
//!
//! # Test matrix (maps to DSL-159 Test Plan)
//!
//!   1. `test_dsl_159_deterministic` — hash() × 2 → equal; across
//!      independent struct constructions with identical fields.
//!   2. `test_dsl_159_mutation_evidence_hash` — flip a byte of
//!      `evidence_hash` → hash differs.
//!   3. `test_dsl_159_mutation_appellant_index` — flip index →
//!      hash differs.
//!   4. `test_dsl_159_mutation_puzzle_hash` — flip a byte of the
//!      payout address → hash differs.
//!   5. `test_dsl_159_mutation_filed_epoch` — flip epoch → hash
//!      differs.
//!   6. `test_dsl_159_mutation_payload_byte` — flip a byte inside
//!      the nested `payload.witness` → hash differs. Pins that
//!      the payload is NOT summarised or sampled — every payload
//!      byte contributes.
//!   7. `test_dsl_159_domain_prefixed` — manual
//!      `SHA-256(DOMAIN_SLASH_APPEAL || bincode(appeal))`
//!      matches `appeal.hash()` exactly. Also asserts the digest
//!      is DIFFERENT from `SHA-256(bincode(appeal))` alone —
//!      proves the domain prefix is actually in the input.

use chia_sha2::Sha256;
use dig_protocol::Bytes32;
use dig_slashing::{
    DOMAIN_SLASH_APPEAL, ProposerAppealGround, ProposerSlashingAppeal, SlashAppeal,
    SlashAppealPayload,
};

// ── fixture ─────────────────────────────────────────────────────

fn sample_appeal() -> SlashAppeal {
    SlashAppeal {
        evidence_hash: Bytes32::new([0xAAu8; 32]),
        appellant_index: 42,
        appellant_puzzle_hash: Bytes32::new([0xBBu8; 32]),
        filed_epoch: 100,
        payload: SlashAppealPayload::Proposer(ProposerSlashingAppeal {
            ground: ProposerAppealGround::HeadersIdentical,
            witness: vec![0x01, 0x02, 0x03, 0x04],
        }),
    }
}

// ── tests ──────────────────────────────────────────────────────

/// DSL-159 row 1: `hash()` is deterministic.
///
/// Two separate struct constructions with IDENTICAL fields must
/// yield the same digest. Also asserts self-consistency: repeated
/// hash() calls on the same instance don't drift (e.g. due to
/// hidden state in the Sha256 accumulator — pinning this guards
/// against a future refactor that mutates `self` during hashing).
#[test]
fn test_dsl_159_deterministic() {
    let a = sample_appeal();
    let b = sample_appeal();

    // Self-consistency: repeated calls agree.
    assert_eq!(a.hash(), a.hash(), "repeated calls on same instance agree");
    assert_eq!(a.hash(), a.hash(), "and again, proving no hidden state");

    // Independent instance, identical fields → same hash.
    assert_eq!(
        a.hash(),
        b.hash(),
        "independent structs with identical fields hash identically \
         — deterministic across constructions",
    );
}

/// DSL-159 row 2: flipping a byte in `evidence_hash` shifts the digest.
///
/// `evidence_hash` is the binding that ties an appeal to a
/// specific PendingSlash (DSL-055 UnknownEvidence check); drift
/// here would let a single appeal shadow slashes it doesn't target.
#[test]
fn test_dsl_159_mutation_evidence_hash() {
    let base = sample_appeal();
    let baseline = base.hash();

    let mut mutated = sample_appeal();
    let mut bytes = [0xAAu8; 32];
    bytes[7] ^= 0x01; // Flip one bit.
    mutated.evidence_hash = Bytes32::new(bytes);

    assert_ne!(
        baseline,
        mutated.hash(),
        "one-bit mutation in evidence_hash must shift the digest",
    );
}

/// DSL-159 row 3: flipping `appellant_index` shifts the digest.
///
/// The index is the whitehouse-bond lookup key (DSL-062) — drift
/// here would misattribute bond locks to the wrong validator.
#[test]
fn test_dsl_159_mutation_appellant_index() {
    let base = sample_appeal();
    let baseline = base.hash();

    let mut mutated = sample_appeal();
    mutated.appellant_index = 43; // was 42

    assert_ne!(
        baseline,
        mutated.hash(),
        "appellant_index contributes to the hash",
    );

    // Also sanity: changing to u32::MAX differs from both above.
    let mut mutated_max = sample_appeal();
    mutated_max.appellant_index = u32::MAX;
    assert_ne!(mutated.hash(), mutated_max.hash());
    assert_ne!(baseline, mutated_max.hash());
}

/// DSL-159 row 4: flipping a byte of `appellant_puzzle_hash` shifts
/// the digest. The puzzle hash is the award payout address on a
/// sustained appeal (DSL-067) — drift here would route rewards
/// incorrectly.
#[test]
fn test_dsl_159_mutation_puzzle_hash() {
    let base = sample_appeal();
    let baseline = base.hash();

    let mut mutated = sample_appeal();
    let mut bytes = [0xBBu8; 32];
    bytes[15] ^= 0x01;
    mutated.appellant_puzzle_hash = Bytes32::new(bytes);

    assert_ne!(
        baseline,
        mutated.hash(),
        "appellant_puzzle_hash contributes to the hash",
    );
}

/// DSL-159 row 5: flipping `filed_epoch` shifts the digest.
///
/// `filed_epoch` anchors the appeal-window-expiry check (DSL-056);
/// digest sensitivity to this field prevents an appellant from
/// re-filing an identical appeal at a different epoch under the
/// same content-addressed hash.
#[test]
fn test_dsl_159_mutation_filed_epoch() {
    let base = sample_appeal();
    let baseline = base.hash();

    let mut mutated = sample_appeal();
    mutated.filed_epoch = 101; // was 100

    assert_ne!(
        baseline,
        mutated.hash(),
        "filed_epoch contributes to the hash",
    );
}

/// DSL-159 row 6: flipping a byte inside the nested payload
/// witness shifts the digest.
///
/// Pins that the payload is NOT summarised or selectively hashed —
/// every byte of `witness` contributes. Critical: a reporter /
/// adjudicator that accepts a truncated payload would silently
/// accept distinct appeals as "the same" appeal under the hash.
#[test]
fn test_dsl_159_mutation_payload_byte() {
    let base = sample_appeal();
    let baseline = base.hash();

    // Flip the last byte of the witness.
    let mut mutated = sample_appeal();
    let SlashAppealPayload::Proposer(ref mut inner) = mutated.payload else {
        unreachable!("fixture uses Proposer variant")
    };
    let last_idx = inner.witness.len() - 1;
    inner.witness[last_idx] ^= 0x01;

    assert_ne!(
        baseline,
        mutated.hash(),
        "one-byte mutation inside payload.witness must shift the digest",
    );

    // Also flip the ground enum — proves enum variant drift shifts
    // the hash (not just witness bytes).
    let mut mutated_ground = sample_appeal();
    let SlashAppealPayload::Proposer(ref mut inner) = mutated_ground.payload else {
        unreachable!()
    };
    inner.ground = ProposerAppealGround::SlotMismatch; // was HeadersIdentical

    assert_ne!(
        baseline,
        mutated_ground.hash(),
        "payload.ground enum variant contributes to the hash",
    );
}

/// DSL-159 row 7: manual `SHA-256(DOMAIN || bincode(appeal))`
/// matches `appeal.hash()` exactly AND differs from an undomained
/// `SHA-256(bincode(appeal))`.
///
/// This pins:
///   (a) the canonical domain-tagged construction against future
///       refactors that might change the prefix.
///   (b) the domain tag is load-bearing — its removal would let an
///       attacker construct an evidence envelope whose bytes collide
///       with an appeal envelope, breaking the pending-book /
///       appeal-history disjointness invariant.
#[test]
fn test_dsl_159_domain_prefixed() {
    let appeal = sample_appeal();

    // Manual construction mirrors the spec formula.
    let encoded = bincode::serialize(&appeal).expect("bincode ser");
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SLASH_APPEAL);
    hasher.update(&encoded);
    let out: [u8; 32] = hasher.finalize();
    let manual = Bytes32::new(out);

    assert_eq!(
        appeal.hash(),
        manual,
        "hash() must equal SHA-256(DOMAIN_SLASH_APPEAL || bincode(self))",
    );

    // Undomained hash — must differ, proving the prefix is in the
    // input (a trivial return of `SHA-256(bincode(self))` would
    // fail this assertion).
    let mut undomained = Sha256::new();
    undomained.update(&encoded);
    let undomained_out: [u8; 32] = undomained.finalize();
    let undomained_hash = Bytes32::new(undomained_out);

    assert_ne!(
        appeal.hash(),
        undomained_hash,
        "domain prefix is load-bearing — appeal.hash() must differ \
         from an undomained SHA-256 over the same bincode bytes",
    );
}
