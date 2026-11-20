use std::any::Any;

use auth_vector::Identity;
#[cfg(feature = "verify")]
use auth_vector::{reason, Binding, Check, Decoded, Outcome, Scheme, Transport};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

pub const NAME: &str = "eth";
pub const PART_LEN: usize = 65;

pub struct EthAddress(pub String);

impl Identity for EthAddress {
    fn canonical(&self) -> String {
        self.0.clone()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

pub fn auth_message(domain: &str, digest: &[u8; 32]) -> String {
    format!("Logos {domain} authorisation: 0x{}", hex::encode(digest))
}

pub fn eip191_digest(msg: &[u8]) -> [u8; 32] {
    let mut envelope = format!("\x19Ethereum Signed Message:\n{}", msg.len()).into_bytes();
    envelope.extend_from_slice(msg);
    keccak256(&envelope)
}

pub fn address_of(vk: &VerifyingKey) -> String {
    let enc = vk.to_encoded_point(false);
    let raw = &enc.as_bytes()[1..];
    let h = keccak256(raw);
    format!("0x{}", hex::encode(&h[12..]))
}

pub fn recover_signer(msg: &[u8], sig: &[u8]) -> Result<String, String> {
    if sig.len() != PART_LEN {
        return Err(format!("signature must be 65 bytes, got {}", sig.len()));
    }
    let digest = eip191_digest(msg);
    let recid_byte = if sig[64] >= 27 { sig[64] - 27 } else { sig[64] };
    let recid = RecoveryId::from_byte(recid_byte).ok_or("invalid recovery id")?;
    let signature = Signature::from_slice(&sig[0..64]).map_err(|e| format!("sig: {e}"))?;
    if signature.normalize_s().is_some() {
        return Err("high-S signature (EIP-2 requires s <= n/2)".into());
    }
    let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid)
        .map_err(|e| format!("recovery failed: {e}"))?;
    Ok(address_of(&vk))
}

pub fn normalize_address(entry: &str) -> Result<String, String> {
    let t = entry.trim().to_ascii_lowercase();
    let h = t.strip_prefix("0x").unwrap_or(&t);
    if h.len() != 40 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "config.allowlist entry {entry:?}: expected a 0x address (40 hex chars)"
        ));
    }
    Ok(format!("0x{h}"))
}

pub struct Eth;

#[cfg(feature = "verify")]
impl Scheme for Eth {
    fn name(&self) -> &'static str {
        NAME
    }
    fn identity_noun(&self) -> &'static str {
        "address"
    }
    fn parse_identity(&self, s: &str) -> Result<String, String> {
        normalize_address(s)
    }
    fn decode<'a>(&self, body: &'a [u8]) -> Outcome<Decoded<'a>> {
        if body.len() < PART_LEN {
            return Outcome::Reject(format!(
                "eth part must be 65 bytes (r||s||recid), got {}",
                body.len()
            ));
        }
        let (part, rest) = body.split_at(PART_LEN);
        Outcome::Ok(Decoded {
            claimed: None,
            part,
            rest,
        })
    }
    fn verify(
        &self,
        _cfg: &dyn Any,
        b: &Binding,
        digest: &[u8; 32],
        d: &Decoded<'_>,
        _t: &Transport<'_>,
    ) -> Check<Box<dyn Identity>> {
        let msg = auth_message(&b.domain, digest);
        Ok(match recover_signer(msg.as_bytes(), d.part) {
            Ok(addr) => Outcome::Ok(Box::new(EthAddress(addr))),
            Err(e) => Outcome::Reject(reason::sig_failed(e)),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use auth_vector::{binding_digest, AuthType, Binding};
    use k256::ecdsa::SigningKey;

    pub(crate) const PK42: [u8; 32] = [0x42; 32];
    pub(crate) const ADDR42: &str = "0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025";
    pub(crate) const DOMAIN: &str = "rln-membership";
    pub(crate) const ACTION: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    pub(crate) const DIGEST: &str =
        "ec0f08d4aca43519bc84af0e4cc1af52d8c3171954f6872bf8bc87c65d8fd7ec";
    pub(crate) const CAST_SIG: &str = "70dc76365127faabdef609b0c82f832147ea39badb276f36146c8a163c58a904248ead70f40d74ff25b835b7f7fe21c638db77590f5aad5e7e362dda85c4c3291c";

    pub(crate) fn binding() -> Binding {
        Binding {
            domain: DOMAIN.into(),
            action: hex::decode(ACTION).unwrap().try_into().unwrap(),
            audience: String::new(),
        }
    }

    pub(crate) fn digest() -> [u8; 32] {
        hex::decode(DIGEST).unwrap().try_into().unwrap()
    }

    #[test]
    fn the_message_names_the_domain_and_the_binding_digest() {
        let d = binding_digest(&AuthType::new("eth", "allowlist"), &binding(), &[]);
        assert_eq!(hex::encode(d), DIGEST);
        assert_eq!(
            auth_message(DOMAIN, &d),
            format!("Logos rln-membership authorisation: 0x{DIGEST}")
        );
        assert_ne!(
            auth_message("account-registry", &d),
            auth_message(DOMAIN, &d)
        );
    }

    #[test]
    fn foundry_cast_signature_recovers() {
        let sig = hex::decode(CAST_SIG).unwrap();
        let msg = auth_message(DOMAIN, &digest());
        assert_eq!(recover_signer(msg.as_bytes(), &sig).unwrap(), ADDR42);
        let other = auth_message("account-registry", &digest());
        assert_ne!(recover_signer(other.as_bytes(), &sig).unwrap(), ADDR42);
        let sk = SigningKey::from_slice(&PK42).unwrap();
        assert_eq!(address_of(sk.verifying_key()), ADDR42);
    }

    #[test]
    fn recid_offsets_and_high_s() {
        let sk = SigningKey::from_slice(&PK42).unwrap();
        let msg = auth_message(DOMAIN, &[0x11; 32]);
        let digest = eip191_digest(msg.as_bytes());
        let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        for offset in [0u8, 27] {
            let mut p = sig.to_bytes().to_vec();
            p.push(recid.to_byte() + offset);
            assert_eq!(
                recover_signer(msg.as_bytes(), &p).unwrap(),
                ADDR42,
                "offset {offset}"
            );
        }
        let (r, s) = sig.split_scalars();
        let high = Signature::from_scalars(r, -*s).unwrap();
        let mut p = high.to_bytes().to_vec();
        p.push(recid.to_byte() ^ 1);
        assert!(recover_signer(msg.as_bytes(), &p)
            .unwrap_err()
            .contains("high-S"));
        assert!(recover_signer(msg.as_bytes(), &p[..64])
            .unwrap_err()
            .contains("65 bytes"));
    }

    #[test]
    fn addresses_normalise() {
        let up = ADDR42.to_uppercase().replace("0X", "0x");
        assert_eq!(normalize_address(&up).unwrap(), ADDR42);
        assert_eq!(normalize_address(&ADDR42[2..]).unwrap(), ADDR42);
        assert_eq!(
            normalize_address(&format!("  {} ", ADDR42.to_uppercase())).unwrap(),
            ADDR42
        );
        for bad in [
            "0x1234",
            "not-an-address",
            &format!("{ADDR42}00"),
            &format!("0x0x{}", &ADDR42[4..]),
        ] {
            assert!(normalize_address(bad)
                .unwrap_err()
                .contains(&format!("{bad:?}")));
        }
    }
}
