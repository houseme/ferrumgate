//! Host key policy (WP-61 §3.3): first-use trust (TOFU) and verification.
//! The decision happens in russh's `check_server_key` — i.e. **before any
//! authentication**: a mismatched host key aborts the handshake and no
//! password or signature is ever sent.
//!
//! Recorded keys carry the negotiated family (`keyType`) plus the
//! `SHA256:…` fingerprint in the `ssh-keygen -l` shape. When the recorded
//! family is missing or the server no longer offers it, the connection
//! retries restricted to the remaining families one by one and accepts
//! only a fingerprint match; the family is then backfilled (see
//! [`crate::ssh::open`]'s attempt list).

use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PublicKey, PublicKeyOrCertificate};

use crate::model::{HostKey, HostKeyType};

/// A host key the server presented during the handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKeyObservation {
    /// The key family when it is one of the supported ones (`None` for
    /// exotic families — first use records the fingerprint only).
    pub key_type: Option<HostKeyType>,
    /// `SHA256:<base64>` fingerprint (unpadded base64, `ssh-keygen -l`).
    pub fingerprint: String,
}

impl HostKeyObservation {
    /// Extracts the observation from russh's key-or-certificate. Certificates
    /// have no supported fingerprint form here and are rejected by policy.
    pub fn from_wire(key: &PublicKeyOrCertificate) -> Option<Self> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            return None;
        };
        Some(Self::from_public_key(key))
    }

    /// Builds the observation from an `ssh-key` public key.
    pub fn from_public_key(key: &PublicKey) -> Self {
        Self {
            key_type: key_type_of(&key.algorithm()),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        }
    }

    /// The stored record a first use would write (family when known).
    pub fn as_record(&self) -> HostKey {
        HostKey {
            key_type: self.key_type,
            fingerprint: self.fingerprint.clone(),
        }
    }
}

/// Maps an `ssh-key` algorithm onto the module's host key family.
pub fn key_type_of(algorithm: &Algorithm) -> Option<HostKeyType> {
    match algorithm {
        Algorithm::Ed25519 | Algorithm::SkEd25519 => Some(HostKeyType::Ed25519),
        Algorithm::Ecdsa { .. } | Algorithm::SkEcdsaSha2NistP256 => Some(HostKeyType::Ecdsa),
        Algorithm::Rsa { .. } => Some(HostKeyType::Rsa),
        Algorithm::Dsa => Some(HostKeyType::Dsa),
        _ => None,
    }
}

/// The wire algorithms a family can negotiate with. `Dsa` has no
/// candidates (legacy keys are not negotiated; the recorded family is
/// simply skipped in the fallback loop).
pub fn algorithms_of(key_type: HostKeyType) -> Vec<Algorithm> {
    match key_type {
        HostKeyType::Ed25519 => vec![Algorithm::Ed25519],
        HostKeyType::Ecdsa => vec![
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
        ],
        HostKeyType::Rsa => vec![
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            Algorithm::Rsa { hash: None },
        ],
        HostKeyType::Dsa => Vec::new(),
    }
}

/// Builds the handshake attempt list for a connection with a recorded
/// host key (WP-61 §3.3):
///
/// 1. the recorded family first (the negotiation then only offers it);
/// 2. when the recorded family is unknown (`None`) or the server no
///    longer offers it, the remaining families, each restricted, accepting
///    only a fingerprint match — the first hit backfills the family.
///
/// A fingerprint mismatch while the recorded family *was* offered is a
/// host key change and aborts without fallback. `None` records means an
/// unrestricted single attempt.
pub struct Attempt {
    /// Wire algorithms offered for the host key; `None` = unrestricted.
    pub restrict: Option<HostKeyType>,
    /// The fingerprint the handshake must match (`None` = accept, first use).
    pub expect: Option<String>,
    /// Whether a success should update the stored family (backfill).
    pub backfill: bool,
}

/// Builds the attempt list for the recorded key (`None` = first use).
pub fn attempts(recorded: Option<&HostKey>) -> Vec<Attempt> {
    let Some(recorded) = recorded else {
        return vec![Attempt {
            restrict: None,
            expect: None,
            backfill: false,
        }];
    };
    let known = recorded
        .key_type
        .filter(|&key_type| !algorithms_of(key_type).is_empty());
    let mut order = Vec::new();
    if let Some(key_type) = known {
        order.push(key_type);
    }
    for key_type in HostKeyType::ALL {
        if !order.contains(&key_type) && !algorithms_of(key_type).is_empty() {
            order.push(key_type);
        }
    }
    order
        .into_iter()
        .map(|key_type| Attempt {
            restrict: Some(key_type),
            expect: Some(recorded.fingerprint.clone()),
            // A hit on a family other than the stored one updates it —
            // that is exactly the backfill (including the "no stored
            // family" case, where any hit fills it).
            backfill: Some(key_type) != recorded.key_type,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_types_map_from_ssh_algorithms() {
        assert_eq!(key_type_of(&Algorithm::Ed25519), Some(HostKeyType::Ed25519));
        assert_eq!(
            key_type_of(&Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384
            }),
            Some(HostKeyType::Ecdsa)
        );
        assert_eq!(
            key_type_of(&Algorithm::Rsa { hash: None }),
            Some(HostKeyType::Rsa)
        );
        assert_eq!(key_type_of(&Algorithm::Dsa), Some(HostKeyType::Dsa));
    }

    #[test]
    fn algorithms_cover_the_family_and_dsa_is_skipped() {
        assert_eq!(algorithms_of(HostKeyType::Ed25519).len(), 1);
        assert_eq!(algorithms_of(HostKeyType::Ecdsa).len(), 3);
        assert_eq!(algorithms_of(HostKeyType::Rsa).len(), 3);
        assert!(algorithms_of(HostKeyType::Dsa).is_empty());
    }

    #[test]
    fn attempts_first_use_is_unrestricted() {
        let attempts = attempts(None);
        assert_eq!(attempts.len(), 1);
        assert!(attempts[0].restrict.is_none());
        assert!(attempts[0].expect.is_none());
        assert!(!attempts[0].backfill);
    }

    #[test]
    fn attempts_try_recorded_family_then_the_others() {
        let recorded = HostKey {
            key_type: Some(HostKeyType::Rsa),
            fingerprint: "SHA256:abc".into(),
        };
        let attempts = attempts(Some(&recorded));
        assert_eq!(attempts[0].restrict, Some(HostKeyType::Rsa));
        assert!(
            !attempts[0].backfill,
            "a match on the recorded family is no update"
        );
        assert_eq!(attempts[1].restrict, Some(HostKeyType::Ed25519));
        assert!(attempts[1].backfill);
        assert_eq!(attempts[2].restrict, Some(HostKeyType::Ecdsa));
        assert!(attempts[2].backfill);
        // DSA has no wire algorithms and is skipped entirely.
        assert!(
            !attempts
                .iter()
                .any(|attempt| attempt.restrict == Some(HostKeyType::Dsa))
        );
        assert!(
            attempts
                .iter()
                .all(|attempt| attempt.expect.as_deref() == Some("SHA256:abc"))
        );
    }

    #[test]
    fn attempts_without_family_backfill_the_first_hit() {
        let recorded = HostKey {
            key_type: None,
            fingerprint: "SHA256:abc".into(),
        };
        let attempts = attempts(Some(&recorded));
        assert_eq!(attempts.len(), 3, "ed25519, ecdsa, rsa");
        assert_eq!(attempts[0].restrict, Some(HostKeyType::Ed25519));
        assert!(
            attempts[0].backfill,
            "the first hit fills the missing family"
        );
        assert!(attempts[1].backfill);
        assert!(attempts[2].backfill);
    }

    #[test]
    fn attempts_dsa_record_falls_back_to_live_families() {
        let recorded = HostKey {
            key_type: Some(HostKeyType::Dsa),
            fingerprint: "SHA256:abc".into(),
        };
        let attempts = attempts(Some(&recorded));
        assert_eq!(
            attempts.len(),
            3,
            "dsa is not negotiable; live families only"
        );
        assert!(attempts.iter().all(|attempt| attempt.backfill));
    }
}
