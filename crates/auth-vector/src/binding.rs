use std::borrow::Cow;

use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use crate::authtype::{name_ok, AuthType};
use crate::hex::{hex32_bytes, strip_0x};
use crate::pieces::{Check, Outcome};
use crate::reason;
use crate::types::{ProduceRequest, VerifyRequest};

pub const MAX_AUDIENCE_LEN: usize = 255;
pub const MAX_DOMAIN_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub domain: String,
    pub action: [u8; 32],
    pub audience: String,
}

pub fn args_object(raw: Option<&Value>) -> Result<Option<Map<String, Value>>, String> {
    Ok(args_object_cow(raw)?.map(Cow::into_owned))
}

pub fn args_object_cow(raw: Option<&Value>) -> Result<Option<Cow<'_, Map<String, Value>>>, String> {
    match raw {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => {
            let inner: Value = serde_json::from_str(s)
                .map_err(|e| format!("args: string is not valid JSON: {e}"))?;
            match inner {
                Value::Null => Ok(None),
                Value::Object(o) => Ok(Some(Cow::Owned(o))),
                other => Err(format!("args: expected JSON object, got {other}")),
            }
        }
        Some(Value::Object(o)) => Ok(Some(Cow::Borrowed(o))),
        Some(v) => Err(format!("args: expected JSON object, got {v}")),
    }
}

pub fn parse_audience(v: Option<&Value>, field: &str) -> Result<String, String> {
    match v {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) if s.len() <= MAX_AUDIENCE_LEN => Ok(s.clone()),
        Some(Value::String(s)) => Err(format!(
            "{field}: at most {MAX_AUDIENCE_LEN} bytes, got {}",
            s.len()
        )),
        Some(v) => Err(format!("{field}: expected string, got {v}")),
    }
}

pub fn validate_domain(domain: &str) -> Result<(), String> {
    if domain.len() <= MAX_DOMAIN_LEN && name_ok(domain) {
        Ok(())
    } else {
        Err(reason::bad_domain(domain))
    }
}

impl Binding {
    pub fn from_produce(req: &ProduceRequest) -> Result<Binding, String> {
        validate_domain(&req.domain)?;
        let action = hex32_bytes("action_hex", &req.action_hex)?;
        let args = args_object_cow(req.args.as_ref())?;
        let audience = parse_audience(args.as_ref().and_then(|o| o.get("audience")), "audience")?;
        Ok(Binding {
            domain: req.domain.clone(),
            action,
            audience,
        })
    }

    pub fn for_verify(req: &VerifyRequest, audience: &str) -> Check<Binding> {
        validate_domain(&req.domain)?;
        let raw = match hex::decode(strip_0x(&req.action_hex)) {
            Ok(a) => a,
            Err(e) => return Ok(Outcome::Reject(reason::action_hex(e))),
        };
        let action: [u8; 32] = match raw.try_into() {
            Ok(a) => a,
            Err(v) => return Ok(Outcome::Reject(reason::action_len(v.len()))),
        };
        Ok(Outcome::Ok(Binding {
            domain: req.domain.clone(),
            action,
            audience: audience.to_owned(),
        }))
    }
}

pub fn domain_separator(domain: &str, t: &AuthType) -> String {
    format!("logos/auth/{domain}/{t}")
}

pub fn binding_digest(t: &AuthType, b: &Binding, extra: &[u8]) -> [u8; 32] {
    let a = b.audience.as_bytes();
    let len = u8::try_from(a.len())
        .expect("invariant: audience is at most MAX_AUDIENCE_LEN bytes (parse_audience)");
    let mut h = Sha256::new();
    h.update(domain_separator(&b.domain, t));
    h.update(b.action);
    h.update([len]);
    h.update(a);
    h.update(extra);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn produce(args: Option<Value>) -> ProduceRequest {
        ProduceRequest {
            auth_type: "t-a".into(),
            domain: "rln-membership".into(),
            action_hex: "01".repeat(32),
            args,
        }
    }

    fn verify_req(domain: &str, action_hex: String) -> VerifyRequest {
        VerifyRequest {
            auth_type: "t-a".into(),
            payload_hex: String::new(),
            domain: domain.into(),
            action_hex,
            config: None,
            peer_id: None,
        }
    }

    #[test]
    fn args_object_unwraps_strings() {
        assert_eq!(args_object(None).unwrap(), None);
        assert_eq!(args_object(Some(&json!(null))).unwrap(), None);
        assert_eq!(args_object(Some(&json!(" "))).unwrap(), None);
        assert_eq!(args_object(Some(&json!("null"))).unwrap(), None);
        let o = args_object(Some(&json!("{\"private_key\":\"0x01\"}")))
            .unwrap()
            .unwrap();
        assert_eq!(o["private_key"], "0x01");
        assert!(args_object(Some(&json!("[1]")))
            .unwrap_err()
            .contains("expected JSON object"));
        assert!(args_object(Some(&json!("{")))
            .unwrap_err()
            .contains("not valid JSON"));
        assert!(args_object(Some(&json!(7)))
            .unwrap_err()
            .contains("expected JSON object"));
    }

    #[test]
    fn domains_are_short_lowercase_names() {
        for good in [
            "rln-membership",
            "account-registry",
            "a",
            "0-9",
            &"d".repeat(64),
        ] {
            assert_eq!(validate_domain(good), Ok(()), "{good:?}");
        }
        for bad in [
            "",
            &"d".repeat(65),
            "RLN-membership",
            "rln/membership",
            "rln membership",
            " rln-membership",
            "rln_membership",
            "rln.membership",
            "dömain",
        ] {
            let e = validate_domain(bad).unwrap_err();
            assert_eq!(e, reason::bad_domain(bad));
            assert!(e.starts_with("domain "), "{e}");
        }
    }

    #[test]
    fn produce_binding_reads_domain_action_and_audience() {
        let b = Binding::from_produce(&produce(None)).unwrap();
        assert_eq!(
            (b.domain.as_str(), b.action, b.audience.as_str()),
            ("rln-membership", [1u8; 32], "")
        );
        let b = Binding::from_produce(&produce(Some(json!({ "audience": "poc" })))).unwrap();
        assert_eq!(b.audience, "poc");
        let b = Binding::from_produce(&produce(Some(json!("{\"audience\": \"s\"}")))).unwrap();
        assert_eq!(b.audience, "s", "a stringified args object counts");
        assert!(
            Binding::from_produce(&produce(Some(json!({ "audience": 1 }))))
                .unwrap_err()
                .starts_with("audience")
        );
        assert!(
            Binding::from_produce(&produce(Some(json!({ "audience": "x".repeat(256) })))).is_err()
        );
        assert!(
            Binding::from_produce(&produce(Some(json!({ "audience": "x".repeat(255) })))).is_ok()
        );

        let mut prefixed = produce(None);
        prefixed.action_hex = format!("0x{}", "AB".repeat(32));
        assert_eq!(Binding::from_produce(&prefixed).unwrap().action, [0xab; 32]);
        let mut short = produce(None);
        short.action_hex = "01".repeat(31);
        assert!(Binding::from_produce(&short)
            .unwrap_err()
            .starts_with("action_hex"));
        let mut bad = produce(None);
        bad.domain = "Account-Registry".into();
        assert_eq!(
            Binding::from_produce(&bad).unwrap_err(),
            reason::bad_domain("Account-Registry")
        );
    }

    #[test]
    fn verify_binding_refuses_a_bad_action_and_errors_on_a_bad_domain() {
        let req = verify_req("account-registry", format!("0X{}", "ab".repeat(32)));
        let Ok(Outcome::Ok(b)) = Binding::for_verify(&req, "aud") else {
            panic!()
        };
        assert_eq!(
            (b.domain.as_str(), b.action, b.audience.as_str()),
            ("account-registry", [0xab; 32], "aud")
        );
        let req = verify_req("account-registry", "ab".repeat(31));
        assert_eq!(
            Binding::for_verify(&req, ""),
            Ok(Outcome::Reject("action must be 32 bytes, got 31".into()))
        );
        let req = verify_req("account-registry", "zz".repeat(32));
        assert!(
            matches!(Binding::for_verify(&req, ""), Ok(Outcome::Reject(r)) if r.starts_with("action hex:"))
        );
        let req = verify_req("", "ab".repeat(32));
        assert_eq!(Binding::for_verify(&req, ""), Err(reason::bad_domain("")));
    }

    #[test]
    fn digest_known_answer() {
        let action: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
        let t = AuthType::new("lez", "allowlist");
        let b = Binding {
            domain: "rln-membership".into(),
            action,
            audience: String::new(),
        };
        assert_eq!(
            domain_separator(&b.domain, &t),
            "logos/auth/rln-membership/lez-allowlist"
        );
        let d = binding_digest(&t, &b, &[]);
        let mut h = Sha256::new();
        h.update(b"logos/auth/rln-membership/lez-allowlist");
        h.update(action);
        h.update([0u8]);
        let by_hand: [u8; 32] = h.finalize().into();
        assert_eq!(d, by_hand);
        assert_eq!(
            hex::encode(d),
            "d1f956730b8338a3d79c3ab19a9b3454b5b3d9b4ba2b78c605f1faf349b023a8"
        );
        let other_domain = Binding {
            domain: "account-registry".into(),
            ..b.clone()
        };
        assert_ne!(binding_digest(&t, &other_domain, &[]), d);
        let mut other_action = b.clone();
        other_action.action[31] ^= 1;
        assert_ne!(binding_digest(&t, &other_action, &[]), d);
        let other_audience = Binding {
            audience: "x".into(),
            ..b.clone()
        };
        assert_ne!(binding_digest(&t, &other_audience, &[]), d);
        assert_ne!(binding_digest(&t, &b, &[1]), d);
        assert_ne!(
            binding_digest(&AuthType::new("logos", "allowlist"), &b, &[]),
            d
        );
    }
}
