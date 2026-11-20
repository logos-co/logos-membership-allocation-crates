use auth_vector::{Binding, Identity, Signer};
use keycard_attest::attest::parse_attestation;
use keycard_client::Keycard;
use serde_json::Value;

use crate::scheme::keycard::{KeycardIdentity, NAME};

pub struct KeycardSigner;

fn identify(challenge: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut kc = Keycard::connect()?;
    kc.select()?;
    if !kc.initialized {
        return Err("card is not initialized".into());
    }
    kc.identify(challenge)
}

impl Signer for KeycardSigner {
    fn scheme(&self) -> &'static str {
        NAME
    }
    fn sign(
        &self,
        _b: &Binding,
        digest: &[u8; 32],
        _args: Option<&Value>,
    ) -> Result<Vec<u8>, String> {
        let tlv = identify(digest)?;
        parse_attestation(&tlv).map_err(|e| format!("parse attestation: {e}"))?;
        Ok(tlv)
    }
    fn identity(&self, _args: Option<&Value>) -> Result<Box<dyn Identity>, String> {
        let tlv = identify(&[0u8; 32])?;
        let att = parse_attestation(&tlv).map_err(|e| format!("parse attestation: {e}"))?;
        Ok(Box::new(KeycardIdentity {
            ident_pub: att.ident_pub,
            ca_sig: att.ca_sig,
        }))
    }
}
