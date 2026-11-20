use serde_json::{json, Value};

pub const CODEC: &str = "/logos/paymaster/rln-membership/1.0.0";

pub const ACTION_KIND: &str = "rln-membership/register";

pub const AUTH_DOMAIN: &str = "rln-membership";

pub const COMMITMENT_LEN: usize = 32;
const RATE_LEN: usize = 8;

pub fn encode(commitment: &[u8; COMMITMENT_LEN], rate_limit: Option<u64>) -> Vec<u8> {
    let mut out = Vec::with_capacity(COMMITMENT_LEN + RATE_LEN);
    out.extend_from_slice(commitment);
    if let Some(rate) = rate_limit {
        out.extend_from_slice(&rate.to_le_bytes());
    }
    out
}

pub fn split(action: &[u8]) -> Result<(&[u8; COMMITMENT_LEN], Option<u64>), String> {
    let malformed = || {
        format!(
            "action holds {} bytes, want a {COMMITMENT_LEN}-byte commitment and an optional {RATE_LEN}-byte rate",
            action.len()
        )
    };
    let (commitment, rest) = action
        .split_first_chunk::<COMMITMENT_LEN>()
        .ok_or_else(malformed)?;
    let rate_limit = match rest {
        [] => None,
        rate => Some(u64::from_le_bytes(
            rate.try_into().map_err(|_| malformed())?,
        )),
    };
    Ok((commitment, rate_limit))
}

const BN254_R_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

pub fn commitment_refusal(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() != COMMITMENT_LEN {
        return Some("identity_commitment must be 32 bytes");
    }
    if bytes.iter().all(|&b| b == 0) {
        return Some("invalid_commitment: zero");
    }
    for (le_byte, r_byte) in bytes.iter().rev().zip(BN254_R_BE.iter()) {
        if le_byte < r_byte {
            return None;
        }
        if le_byte > r_byte {
            return Some(
                "invalid_commitment: not a BN254 field element (little-endian value >= r)",
            );
        }
    }
    Some("invalid_commitment: not a BN254 field element (little-endian value >= r)")
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grant {
    pub leaf_index: u64,
    pub tx_hash: String,
    pub registry: String,
}

impl Grant {
    pub fn encode(&self) -> Vec<u8> {
        json!({
            "leaf_index": self.leaf_index,
            "tx_hash": self.tx_hash,
            "registry": self.registry,
        })
        .to_string()
        .into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Grant, String> {
        let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("grant: {e}"))?;
        let text = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("grant: no {k}"))
        };
        Ok(Grant {
            leaf_index: v
                .get("leaf_index")
                .and_then(Value::as_u64)
                .ok_or("grant: no leaf_index")?,
            tx_hash: text("tx_hash")?,
            registry: text("registry")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_action_is_the_commitment_then_an_optional_rate() {
        let commitment = [9u8; COMMITMENT_LEN];
        let bare = encode(&commitment, None);
        assert_eq!(bare, commitment);
        assert_eq!(split(&bare).unwrap(), (&commitment, None));
        let rated = encode(&commitment, Some(100));
        assert_eq!(rated.len(), COMMITMENT_LEN + 8);
        assert_eq!(&rated[COMMITMENT_LEN..], [100, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(split(&rated).unwrap(), (&commitment, Some(100)));
        assert_ne!(encode(&commitment, Some(0)), bare);
        for bad in [&rated[..10], &rated[..COMMITMENT_LEN + 3], &[][..]] {
            assert!(
                split(bad)
                    .unwrap_err()
                    .contains("want a 32-byte commitment"),
                "{}",
                bad.len()
            );
        }
    }

    #[test]
    fn commitment_refusal_mirrors_the_registry() {
        let mut r_le = BN254_R_BE;
        r_le.reverse();
        assert!(commitment_refusal(&r_le)
            .unwrap()
            .contains("invalid_commitment"));
        let mut r_minus_1 = r_le;
        r_minus_1[0] -= 1;
        assert_eq!(commitment_refusal(&r_minus_1), None);
        assert_eq!(
            commitment_refusal(&[0xff; 32]).unwrap(),
            "invalid_commitment: not a BN254 field element (little-endian value >= r)"
        );
        assert_eq!(
            commitment_refusal(&[0u8; 32]).unwrap(),
            "invalid_commitment: zero"
        );
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(commitment_refusal(&one), None);
        let mut small_top = [0xab; 32];
        small_top[31] = 0x0a;
        assert_eq!(commitment_refusal(&small_top), None);
        assert!(commitment_refusal(&[1u8; 31]).unwrap().contains("32 bytes"));
    }

    #[test]
    fn a_grant_round_trips() {
        let g = Grant {
            leaf_index: 56,
            tx_hash: "abcd".into(),
            registry: "dd".repeat(32),
        };
        assert_eq!(Grant::decode(&g.encode()).unwrap(), g);
        assert_eq!(
            Grant::decode(b"{\"leaf_index\":1,\"tx_hash\":\"\"}").unwrap_err(),
            "grant: no registry"
        );
        assert_eq!(
            Grant::decode(b"{\"tx_hash\":\"\",\"registry\":\"\"}").unwrap_err(),
            "grant: no leaf_index"
        );
    }
}
