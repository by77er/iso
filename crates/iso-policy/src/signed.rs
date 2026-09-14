//! Fleet-signed policies.
//!
//! A host in a fleet holds the policy of every VM it runs and hands it to
//! the edge, which relays it to the proxy tier in the tunnel headers. Left
//! there, the tier would be trusting the host: a compromised host could
//! present any principal and any rule set and have credentials injected
//! accordingly. So the fleet, which decides policy, signs it: the claims
//! below, as canonical JSON, under an ed25519 key only the fleet holds. The
//! host stores the signed blob unchanged, the edge relays it unchanged, and
//! the tier verifies the signature, the expiry, and that the host named in
//! the claims is the edge it is talking to. A host can then present only
//! policies the fleet issued to it, for VMs placed on it, and only until
//! they expire.
//!
//! The signature covers the exact bytes in [`SignedPolicy::claims`]; the
//! claims are parsed only after they verify.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
pub use iso_common::identify::SignedPolicy;
use ring::signature::{Ed25519KeyPair, KeyPair as _, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// What the fleet vouches for. Field order is the canonical order; the
/// signer serializes it and the verifier parses what it verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyClaims {
    /// The host the VM is placed on: must equal the edge's certificate name.
    pub host: String,
    pub vm: String,
    /// `"proxy" | "deny"` (`"allow"` while it still exists).
    pub egress: String,
    pub principal: Option<String>,
    /// The effective rule set, expanded, in `iso-policy` syntax.
    pub rules: Vec<String>,
    pub policy_gen: u64,
    /// Seconds since the epoch after which the tier refuses it.
    pub expires: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("signed policy is not base64: {0}")]
    Encoding(String),
    #[error("signature does not verify")]
    Signature,
    #[error("signed policy expired {0}s ago")]
    Expired(u64),
    #[error("signed claims are not valid JSON: {0}")]
    Claims(String),
    #[error("public key is not a 32-byte ed25519 key")]
    Key,
}

/// The fleet's signing key.
pub struct Signer {
    key: Ed25519KeyPair,
}

impl Signer {
    /// A fresh key. The PKCS#8 document is what to keep.
    pub fn generate() -> Result<(Self, Vec<u8>), ring::error::Unspecified> {
        let rng = ring::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng)?;
        let key = Ed25519KeyPair::from_pkcs8(doc.as_ref()).map_err(|_| ring::error::Unspecified)?;
        Ok((Self { key }, doc.as_ref().to_vec()))
    }

    pub fn from_pkcs8(doc: &[u8]) -> Result<Self, ring::error::KeyRejected> {
        Ok(Self { key: Ed25519KeyPair::from_pkcs8(doc)? })
    }

    /// The public key, base64 of the raw 32 bytes: what a verifier is given.
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.key.public_key().as_ref())
    }

    pub fn sign(&self, claims: &PolicyClaims) -> SignedPolicy {
        let json = serde_json::to_vec(claims).expect("claims serialize");
        let sig = self.key.sign(&json);
        SignedPolicy { claims: B64.encode(json), sig: B64.encode(sig.as_ref()) }
    }
}

/// The fleet's public key, as a tier holds it.
#[derive(Clone, Debug)]
pub struct Verifier {
    public: Vec<u8>,
}

impl Verifier {
    pub fn from_b64(s: &str) -> Result<Self, VerifyError> {
        let public = B64.decode(s.trim()).map_err(|e| VerifyError::Encoding(e.to_string()))?;
        if public.len() != 32 {
            return Err(VerifyError::Key);
        }
        Ok(Self { public })
    }

    /// Verify `signed` at wall time `now` (seconds since the epoch) and
    /// return the claims it carries.
    pub fn verify_at(&self, signed: &SignedPolicy, now: u64) -> Result<PolicyClaims, VerifyError> {
        let json = B64.decode(&signed.claims).map_err(|e| VerifyError::Encoding(e.to_string()))?;
        let sig = B64.decode(&signed.sig).map_err(|e| VerifyError::Encoding(e.to_string()))?;
        UnparsedPublicKey::new(&ED25519, &self.public)
            .verify(&json, &sig)
            .map_err(|_| VerifyError::Signature)?;
        let claims: PolicyClaims = serde_json::from_slice(&json).map_err(|e| VerifyError::Claims(e.to_string()))?;
        if claims.expires <= now {
            return Err(VerifyError::Expired(now - claims.expires));
        }
        Ok(claims)
    }

    pub fn verify(&self, signed: &SignedPolicy) -> Result<PolicyClaims, VerifyError> {
        self.verify_at(signed, now())
    }

    /// Verify the signature but not the expiry: for the signer deciding
    /// whether a signature is its own before renewing it. Never for a
    /// decision about traffic.
    pub fn verify_ignoring_expiry(&self, signed: &SignedPolicy) -> Result<PolicyClaims, VerifyError> {
        self.verify_at(signed, 0)
    }
}

/// The claims as written, **without** checking the signature. For a host
/// checking that what it was handed describes the VM it is storing it on;
/// never for a decision about traffic.
pub fn claims_unverified(signed: &SignedPolicy) -> Result<PolicyClaims, VerifyError> {
    let json = B64.decode(&signed.claims).map_err(|e| VerifyError::Encoding(e.to_string()))?;
    serde_json::from_slice(&json).map_err(|e| VerifyError::Claims(e.to_string()))
}

/// Seconds since the epoch.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(host: &str, expires: u64) -> PolicyClaims {
        PolicyClaims {
            host: host.into(),
            vm: "vm-1".into(),
            egress: "proxy".into(),
            principal: Some("alice".into()),
            rules: vec!["allow https://api.example.test/**".into()],
            policy_gen: 3,
            expires,
        }
    }

    #[test]
    fn signs_and_verifies_and_the_claims_come_back_intact() {
        let (signer, doc) = Signer::generate().unwrap();
        let again = Signer::from_pkcs8(&doc).unwrap();
        assert_eq!(signer.public_key_b64(), again.public_key_b64(), "the document is the key");
        let signed = again.sign(&claims("host-a", 1_000));
        let v = Verifier::from_b64(&signer.public_key_b64()).unwrap();
        assert_eq!(v.verify_at(&signed, 999).unwrap(), claims("host-a", 1_000));
        assert_eq!(claims_unverified(&signed).unwrap().host, "host-a");
    }

    #[test]
    fn tampering_another_key_and_expiry_are_refused() {
        let (signer, _) = Signer::generate().unwrap();
        let signed = signer.sign(&claims("host-a", 1_000));
        let v = Verifier::from_b64(&signer.public_key_b64()).unwrap();

        // Claims re-encoded with a different host, signature kept.
        let mut forged = claims_unverified(&signed).unwrap();
        forged.host = "host-b".into();
        let tampered = SignedPolicy {
            claims: B64.encode(serde_json::to_vec(&forged).unwrap()),
            sig: signed.sig.clone(),
        };
        assert_eq!(v.verify_at(&tampered, 1).unwrap_err(), VerifyError::Signature);

        let (other, _) = Signer::generate().unwrap();
        let elsewhere = other.sign(&claims("host-a", 1_000));
        assert_eq!(v.verify_at(&elsewhere, 1).unwrap_err(), VerifyError::Signature);

        assert_eq!(v.verify_at(&signed, 1_000).unwrap_err(), VerifyError::Expired(0));
        assert_eq!(v.verify_at(&signed, 1_010).unwrap_err(), VerifyError::Expired(10));

        assert_eq!(v.verify_at(&SignedPolicy { claims: "!!".into(), sig: signed.sig.clone() }, 1).unwrap_err(),
            VerifyError::Encoding("Invalid symbol 33, offset 0.".into()));
        assert_eq!(Verifier::from_b64("AAAA").unwrap_err(), VerifyError::Key);
    }
}
