use base58::FromBase58;
use base64::Engine;
use sha2::{Digest, Sha256};

pub mod envelope;
pub mod proto;

pub const MAX_ADVERTISED_PAIRS: usize = 8;
const PAIR_DIGEST_LEN: usize = 3;

pub fn pair_digest(scope: &str, auth_type: &str) -> [u8; PAIR_DIGEST_LEN] {
    let h = Sha256::digest(format!("{scope}/{auth_type}").as_bytes());
    let mut d = [0u8; PAIR_DIGEST_LEN];
    d.copy_from_slice(&h[..PAIR_DIGEST_LEN]);
    d
}

pub fn service_data(pairs: &[(&str, &str)]) -> Result<String, String> {
    let mut digests: Vec<[u8; PAIR_DIGEST_LEN]> =
        pairs.iter().map(|(s, t)| pair_digest(s, t)).collect();
    digests.sort_unstable();
    digests.dedup();
    if digests.len() > MAX_ADVERTISED_PAIRS {
        return Err(format!(
            "an advertisement carries at most {MAX_ADVERTISED_PAIRS} (scope, auth type) pairs, not {}",
            digests.len()
        ));
    }
    Ok(base64::engine::general_purpose::STANDARD_NO_PAD.encode(digests.concat()))
}

pub fn service_data_lists(data: &[u8], scope: &str, auth_type: &str) -> bool {
    let Ok(bytes) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(data) else {
        return false;
    };
    let want = pair_digest(scope, auth_type);
    bytes.chunks_exact(PAIR_DIGEST_LEN).any(|c| c == want)
}

pub fn canonical_account(s: &str) -> Result<String, String> {
    let s = s.trim();
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(h.to_ascii_lowercase());
    }
    let bytes = s
        .from_base58()
        .map_err(|e| format!("account '{s}': neither 64 hex nor base58 ({e:?})"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "account '{s}': base58 decodes to {} bytes, want 32",
            bytes.len()
        ));
    }
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_data_names_each_served_pair_once_and_fits_libp2p() {
        let (d, m) = (hex::encode([0xd; 32]), hex::encode([0xa; 32]));
        let pairs = [
            (d.as_str(), "peer-any"),
            (m.as_str(), "peer-any"),
            (d.as_str(), "eth-allowlist"),
            (d.as_str(), "peer-any"),
        ];
        let data = service_data(&pairs).unwrap();
        assert_eq!(data.len(), 3 * 4, "{data}");
        for (r, t) in &pairs {
            assert!(service_data_lists(data.as_bytes(), r, t), "{r}/{t}");
        }
        assert!(!service_data_lists(data.as_bytes(), &m, "eth-allowlist"));
        assert!(!service_data_lists(data.as_bytes(), &d, ""));
        assert!(!service_data_lists(b"", &d, "peer-any"));
        assert!(!service_data_lists(b"not*base64", &d, "peer-any"));

        let open = service_data(&[(d.as_str(), "")]).unwrap();
        assert!(service_data_lists(open.as_bytes(), &d, ""));

        let types: Vec<String> = (0..9u8).map(|i| format!("t{i}")).collect();
        let eight: Vec<(&str, &str)> = types[..8]
            .iter()
            .map(|t| (d.as_str(), t.as_str()))
            .collect();
        assert_eq!(service_data(&eight).unwrap().len(), 32);
        let nine: Vec<(&str, &str)> = types.iter().map(|t| (d.as_str(), t.as_str())).collect();
        assert!(service_data(&nine).unwrap_err().contains("at most 8"));
        assert_eq!(service_data(&[]).unwrap(), "");
    }

    #[test]
    fn accounts_normalise_to_lowercase_hex() {
        let hex = "ab".repeat(32);
        assert_eq!(
            canonical_account(&format!(" 0X{} ", hex.to_uppercase())).unwrap(),
            hex
        );
        let b58 = "CZ8YUVdk7znjrUmnb5n7kgySk9yRAsQDYmyCxzfSky9t";
        assert_eq!(canonical_account(b58).unwrap(), hex);
        assert!(canonical_account("ab0")
            .unwrap_err()
            .contains("neither 64 hex nor base58"));
        assert!(canonical_account("11").unwrap_err().contains("want 32"));
    }
}
