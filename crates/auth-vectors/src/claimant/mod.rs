pub mod pow_claim;

use auth_vector::{Binding, Claimant};
use serde_json::Value;

pub use pow_claim::PowClaimant;

use crate::scheme::keycard::NAME as KEYCARD;

pub struct AllowlistClaimant;

impl Claimant for AllowlistClaimant {
    fn authoriser(&self) -> &'static str {
        "allowlist"
    }
    fn accepts(&self, _scheme: &str) -> bool {
        true
    }
    fn gather(&self, _b: &Binding, _args: Option<&Value>) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
    fn extra(&self, _evidence: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

pub struct AnyClaimant;

impl Claimant for AnyClaimant {
    fn authoriser(&self) -> &'static str {
        "any"
    }
    fn accepts(&self, _scheme: &str) -> bool {
        true
    }
    fn gather(&self, _b: &Binding, _args: Option<&Value>) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
    fn extra(&self, _evidence: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

pub struct AttestationClaimant;

impl Claimant for AttestationClaimant {
    fn authoriser(&self) -> &'static str {
        "attestation"
    }
    fn accepts(&self, scheme: &str) -> bool {
        scheme == KEYCARD
    }
    fn gather(&self, _b: &Binding, _args: Option<&Value>) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
    fn extra(&self, _evidence: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}
