use auth_vector::{Binding, Identity, Signer};
use k256::ecdsa::SigningKey;
use serde_json::Value;

use super::{private_key_arg, KeySource};
use crate::scheme::eth::{address_of, auth_message, eip191_digest, EthAddress, NAME};

pub struct EthSigner(pub Box<dyn KeySource>);

impl EthSigner {
    fn key(&self, args: Option<&Value>) -> Result<SigningKey, String> {
        let bytes = match private_key_arg(args)? {
            Some(k) => k,
            None => self.0.key(args)?,
        };
        SigningKey::from_slice(&bytes).map_err(|e| format!("private key: {e}"))
    }
}

impl Signer for EthSigner {
    fn scheme(&self) -> &'static str {
        NAME
    }
    fn sign(
        &self,
        b: &Binding,
        digest: &[u8; 32],
        args: Option<&Value>,
    ) -> Result<Vec<u8>, String> {
        let key = self.key(args)?;
        let msg = auth_message(&b.domain, digest);
        let (sig, recid) = key
            .sign_prehash_recoverable(&eip191_digest(msg.as_bytes()))
            .map_err(|e| format!("sign: {e}"))?;
        let mut out = sig.to_bytes().to_vec();
        out.push(recid.to_byte());
        Ok(out)
    }
    fn identity(&self, args: Option<&Value>) -> Result<Box<dyn Identity>, String> {
        Ok(Box::new(EthAddress(address_of(
            self.key(args)?.verifying_key(),
        ))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::eth::tests::{binding, digest, ADDR42, CAST_SIG, PK42};
    use crate::signer::StaticKey;

    #[test]
    fn matches_foundry_cast_vector() {
        let s = EthSigner(Box::new(StaticKey(PK42)));
        let ours = s.sign(&binding(), &digest(), None).unwrap();
        assert_eq!(
            hex::encode(&ours[..64]),
            &CAST_SIG[..128],
            "r||s differs from cast"
        );
        let v = u8::from_str_radix(&CAST_SIG[128..], 16).unwrap();
        assert_eq!(ours[64], v - 27);
        assert_eq!(s.identity(None).unwrap().canonical(), ADDR42);
        let mut other = binding();
        other.domain = "account-registry".into();
        assert_ne!(s.sign(&other, &digest(), None).unwrap(), ours);
    }

    #[test]
    fn private_key_arg_overrides_the_source() {
        let s = EthSigner(Box::new(StaticKey([1; 32])));
        let args = serde_json::json!({ "private_key": format!("0x{}", hex::encode(PK42)) });
        assert_eq!(s.identity(Some(&args)).unwrap().canonical(), ADDR42);
        assert_ne!(s.identity(None).unwrap().canonical(), ADDR42);
        let bad = serde_json::json!({ "private_key": "0x01" });
        assert!(s.identity(Some(&bad)).err().unwrap().contains("32 bytes"));
    }
}
