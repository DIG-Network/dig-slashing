//! Requirement DSL-138: `PublicKeyLookup::pubkey_of(idx)`.
//!
//!   - Known idx → `Some(&PublicKey)`.
//!   - Unknown idx → `None`.
//!   - Blanket impl `impl<T: ValidatorView + ?Sized>
//!     PublicKeyLookup for T` delegates to
//!     `ValidatorEntry::public_key`.
//!
//! Traces to: docs/resources/SPEC.md §15.2.
//!
//! # Role
//!
//! DSL-006 `IndexedAttestation::verify_signature` materialises
//! the pubkey set for the aggregate BLS verify by looking up
//! every `attesting_indices[i]` via `PublicKeyLookup`. The
//! blanket impl lets callers pass a single `ValidatorView`
//! object that satisfies both the state-read surface AND the
//! pubkey-lookup surface — no redundant trait-object pointers.
//!
//! # Test matrix (maps to DSL-138 Test Plan + acceptance)
//!
//!   1. `test_dsl_138_known_returns_key` — live idx returns
//!      Some via a direct PublicKeyLookup impl
//!   2. `test_dsl_138_unknown_none` — unknown idx returns None
//!   3. `test_dsl_138_blanket_impl_via_validator_view` — a
//!      `ValidatorView` passes type-check as
//!      `&dyn PublicKeyLookup` and returns the expected key
//!      through the blanket

use std::cell::RefCell;

use chia_bls::{PublicKey, SecretKey};
use dig_protocol::Bytes32;
use dig_slashing::{PublicKeyLookup, ValidatorEntry, ValidatorView};

fn deterministic_pk(seed: u8) -> PublicKey {
    // Derive a distinct key per seed so tests can verify the
    // correct entry returned (identity, not shape). chia-bls
    // SecretKey::from_seed requires a 32-byte seed.
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    SecretKey::from_seed(&bytes).public_key()
}

struct MockValidator {
    pk: PublicKey,
    ph: Bytes32,
    stake: RefCell<u64>,
    is_slashed: RefCell<bool>,
}

impl ValidatorEntry for MockValidator {
    fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    fn puzzle_hash(&self) -> Bytes32 {
        self.ph
    }
    fn effective_balance(&self) -> u64 {
        *self.stake.borrow()
    }
    fn is_slashed(&self) -> bool {
        *self.is_slashed.borrow()
    }
    fn activation_epoch(&self) -> u64 {
        0
    }
    fn exit_epoch(&self) -> u64 {
        u64::MAX
    }
    fn is_active_at_epoch(&self, _: u64) -> bool {
        true
    }
    fn slash_absolute(&mut self, _: u64, _: u64) -> u64 {
        0
    }
    fn credit_stake(&mut self, _: u64) -> u64 {
        0
    }
    fn restore_status(&mut self) -> bool {
        false
    }
    fn schedule_exit(&mut self, _: u64) {}
}

struct MockValidatorSet {
    entries: Vec<MockValidator>,
}
impl MockValidatorSet {
    fn with_keys(seeds: &[u8]) -> Self {
        Self {
            entries: seeds
                .iter()
                .map(|&seed| MockValidator {
                    pk: deterministic_pk(seed),
                    ph: Bytes32::new([seed; 32]),
                    stake: RefCell::new(32_000_000_000),
                    is_slashed: RefCell::new(false),
                })
                .collect(),
        }
    }
}
impl ValidatorView for MockValidatorSet {
    fn get(&self, idx: u32) -> Option<&dyn ValidatorEntry> {
        self.entries
            .get(idx as usize)
            .map(|v| v as &dyn ValidatorEntry)
    }
    fn get_mut(&mut self, idx: u32) -> Option<&mut dyn ValidatorEntry> {
        self.entries
            .get_mut(idx as usize)
            .map(|v| v as &mut dyn ValidatorEntry)
    }
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// DSL-138 row 1: blanket impl returns Some(&PublicKey) for
/// live indices, and the key identity matches the ValidatorEntry's
/// own public_key.
#[test]
fn test_dsl_138_known_returns_key() {
    let vs = MockValidatorSet::with_keys(&[1, 2, 3]);

    // Direct access through ValidatorView...
    let direct = vs.get(1).unwrap().public_key();

    // ...and through the PublicKeyLookup blanket.
    let via_blanket = PublicKeyLookup::pubkey_of(&vs, 1).unwrap();

    assert_eq!(
        direct, via_blanket,
        "blanket delegates to ValidatorEntry::public_key"
    );
}

/// DSL-138 row 2: unknown idx → None via the blanket.
#[test]
fn test_dsl_138_unknown_none() {
    let vs = MockValidatorSet::with_keys(&[1, 2, 3]);
    assert!(PublicKeyLookup::pubkey_of(&vs, 3).is_none(), "len boundary");
    assert!(PublicKeyLookup::pubkey_of(&vs, 100).is_none());
    assert!(PublicKeyLookup::pubkey_of(&vs, u32::MAX).is_none());
}

/// DSL-138 row 3: a ValidatorView compiles as &dyn PublicKeyLookup.
/// This test is a type-system assertion: the blanket impl has
/// to compose with the ValidatorView trait object so a single
/// consumer (like DSL-006 IndexedAttestation::verify_signature)
/// can accept either trait without parameter duplication.
#[test]
fn test_dsl_138_blanket_impl_via_validator_view() {
    let vs = MockValidatorSet::with_keys(&[7, 8]);

    // Exercise the blanket by calling pubkey_of on a function
    // that accepts `&dyn PublicKeyLookup`.
    fn pluck(lookup: &dyn PublicKeyLookup, idx: u32) -> Option<&PublicKey> {
        lookup.pubkey_of(idx)
    }

    let k0 = pluck(&vs, 0).unwrap();
    let k1 = pluck(&vs, 1).unwrap();
    let missing = pluck(&vs, 2);

    assert_eq!(k0, &deterministic_pk(7));
    assert_eq!(k1, &deterministic_pk(8));
    assert!(missing.is_none());
}
