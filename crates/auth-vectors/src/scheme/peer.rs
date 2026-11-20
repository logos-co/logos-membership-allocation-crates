use std::any::Any;

#[cfg(feature = "verify")]
use auth_vector::{reason, Binding, Check, Decoded, Outcome, Scheme, Transport};
use auth_vector::{strip_0x, Identity};
use base58::FromBase58;

pub const NAME: &str = "peer";

pub struct PeerId(pub String);

impl Identity for PeerId {
    fn canonical(&self) -> String {
        self.0.clone()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn parse_peer_id(s: &str) -> Result<String, String> {
    let s = s.trim();
    let h = strip_0x(s);
    let bytes =
        if !h.is_empty() && h.len().is_multiple_of(2) && h.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(h).map_err(|e| format!("peer id '{s}': {e}"))?
        } else {
            s.from_base58()
                .map_err(|e| format!("peer id '{s}': neither hex nor base58 ({e:?})"))?
        };
    if bytes.len() < 3 || bytes[1] as usize != bytes.len() - 2 {
        return Err(format!(
            "peer id '{s}': {} bytes is not a multihash",
            bytes.len()
        ));
    }
    Ok(hex::encode(bytes))
}

pub struct Peer;

#[cfg(feature = "verify")]
impl Scheme for Peer {
    fn name(&self) -> &'static str {
        NAME
    }
    fn identity_noun(&self) -> &'static str {
        "peer"
    }
    fn parse_identity(&self, s: &str) -> Result<String, String> {
        parse_peer_id(s)
    }
    fn decode<'a>(&self, body: &'a [u8]) -> Outcome<Decoded<'a>> {
        let (part, rest) = body.split_at(0);
        Outcome::Ok(Decoded {
            claimed: None,
            part,
            rest,
        })
    }
    fn verify(
        &self,
        _cfg: &dyn Any,
        _b: &Binding,
        _digest: &[u8; 32],
        _d: &Decoded<'_>,
        t: &Transport<'_>,
    ) -> Check<Box<dyn Identity>> {
        let Some(raw) = t.peer_id.map(str::trim).filter(|p| !p.is_empty()) else {
            return Err(reason::TRANSPORT_PEER_UNKNOWN.into());
        };
        Ok(Outcome::Ok(Box::new(PeerId(parse_peer_id(raw)?))))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const ED25519_B58: &str = "12D3KooWA1yXQfKD3c8QznGkpf1ZepPH1FQKwAwMxbTh1feQsapZ";
    pub(crate) const SECP_B58: &str = "16Uiu2HAkyiMKmjcAj4FS5jot1jMZB73mnY3wJnSTKZmTBhrFJEaT";
    pub(crate) const QM_B58: &str = "QmQfvdZYmpvysswRYhPy2cDQPv47pWooqarKGq98uJgpSk";

    #[test]
    fn base58_and_hex_normalise_to_the_same_multihash_hex() {
        let ed = parse_peer_id(ED25519_B58).unwrap();
        assert!(ed.starts_with("00240801"), "{ed}");
        assert_eq!(ed.len(), 76);
        assert_eq!(
            parse_peer_id(&format!("0x{}", ed.to_uppercase())).unwrap(),
            ed
        );
        let secp = parse_peer_id(SECP_B58).unwrap();
        assert!(secp.starts_with("00250802"), "{secp}");
        assert_eq!(secp.len(), 78);
        let qm = parse_peer_id(QM_B58).unwrap();
        assert!(qm.starts_with("1220"), "{qm}");
        assert_eq!(qm.len(), 68);
        assert!(parse_peer_id("").is_err());
        assert!(parse_peer_id("0x1220")
            .unwrap_err()
            .contains("not a multihash"));
        assert!(parse_peer_id("not*base58")
            .unwrap_err()
            .contains("neither hex nor base58"));
    }

    #[cfg(feature = "verify")]
    #[test]
    fn the_identity_is_the_transports_or_nothing() {
        let d = match Peer.decode(b"tail") {
            Outcome::Ok(d) => d,
            Outcome::Reject(r) => panic!("{r}"),
        };
        assert!(d.part.is_empty() && d.rest == b"tail" && d.claimed.is_none());
        let b = Binding {
            domain: "rln-membership".into(),
            action: [1; 32],
            audience: String::new(),
        };
        let ok = Peer
            .verify(
                &(),
                &b,
                &[0; 32],
                &d,
                &Transport {
                    peer_id: Some(SECP_B58),
                },
            )
            .unwrap();
        let Outcome::Ok(id) = ok else { panic!() };
        assert_eq!(id.canonical(), parse_peer_id(SECP_B58).unwrap());
        let Err(e) = Peer.verify(&(), &b, &[0; 32], &d, &Transport::default()) else {
            panic!()
        };
        assert_eq!(e, reason::TRANSPORT_PEER_UNKNOWN);
        assert!(Peer
            .verify(
                &(),
                &b,
                &[0; 32],
                &d,
                &Transport {
                    peer_id: Some("??")
                }
            )
            .is_err());
    }
}
