use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PRODUCE_METHOD: &str = "produce_auth";
pub const VERIFY_METHOD: &str = "verify_auth";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProduceRequest {
    pub auth_type: String,
    pub domain: String,
    pub action_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Value>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ProduceRequestRef<'a> {
    pub auth_type: &'a str,
    pub domain: &'a str,
    pub action_hex: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<&'a Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProduceReply {
    pub payload_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub auth_type: String,
    pub payload_hex: String,
    pub domain: String,
    pub action_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct VerifyRequestRef<'a> {
    pub auth_type: &'a str,
    pub payload_hex: &'a str,
    pub domain: &'a str,
    pub action_hex: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

impl Verdict {
    pub fn accept(
        identity: impl Into<String>,
        scheme: impl Into<String>,
        nullifier: Option<String>,
    ) -> Self {
        Verdict {
            ok: true,
            reason: None,
            nullifier,
            identity: Some(identity.into()),
            scheme: Some(scheme.into()),
        }
    }
    pub fn reject(reason: impl Into<String>) -> Self {
        Verdict {
            ok: false,
            reason: Some(reason.into()),
            nullifier: None,
            identity: None,
            scheme: None,
        }
    }
}

pub fn namespaced_nullifier(scope: &str, auth_type: &str, nullifier: &str) -> String {
    format!("{scope}:{auth_type}:{nullifier}")
}

pub(crate) fn error_reply(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

pub fn parse_produce_reply(reply: &Value) -> Result<ProduceReply, String> {
    if let Some(e) = reply.get("error").and_then(Value::as_str) {
        return Err(e.to_string());
    }
    ProduceReply::deserialize(reply).map_err(|e| format!("produce_auth reply: {e}"))
}

pub fn parse_verdict(reply: &Value) -> Result<Verdict, String> {
    if let Some(e) = reply.get("error").and_then(Value::as_str) {
        return Err(e.to_string());
    }
    Verdict::deserialize(reply).map_err(|e| format!("verify_auth reply: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_parsers_surface_the_error_envelope() {
        let ok = serde_json::json!({ "payload_hex": "aa" });
        assert_eq!(parse_produce_reply(&ok).unwrap().payload_hex, "aa");
        let err = serde_json::json!({ "error": "boom" });
        assert_eq!(parse_produce_reply(&err).unwrap_err(), "boom");

        let verdict = serde_json::json!({ "ok": true, "nullifier": "n" });
        let v = parse_verdict(&verdict).unwrap();
        assert_eq!(v.nullifier.as_deref(), Some("n"));
        assert_eq!(
            (v.identity, v.scheme),
            (None, None),
            "identity and scheme default when absent"
        );
        assert_eq!(parse_verdict(&err).unwrap_err(), "boom");
    }

    #[test]
    fn verdicts_carry_identity_and_scheme_on_accept_only() {
        let a = Verdict::accept("0xabc", "eth", Some("0xabc".into()));
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "ok": true, "nullifier": "0xabc", "identity": "0xabc", "scheme": "eth" })
        );
        assert_eq!(parse_verdict(&v).unwrap(), a);

        let r = Verdict::reject("no");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v, serde_json::json!({ "ok": false, "reason": "no" }));
        assert_eq!(parse_verdict(&v).unwrap(), r);
    }

    #[test]
    fn request_shapes_round_trip_with_optional_fields_omitted() {
        let req = VerifyRequest {
            auth_type: "t-a".into(),
            payload_hex: "aa".into(),
            domain: "rln-membership".into(),
            action_hex: "bb".into(),
            config: None,
            peer_id: None,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert!(v.get("config").is_none(), "unset config must be omitted");
        assert!(v.get("peer_id").is_none(), "unset peer_id must be omitted");
        let back: VerifyRequest = serde_json::from_value(v).unwrap();
        assert_eq!(
            (back.auth_type.as_str(), back.domain.as_str()),
            ("t-a", "rln-membership")
        );

        let no_domain = serde_json::json!({
            "auth_type": "t-a", "payload_hex": "aa", "action_hex": "bb"
        });
        assert!(serde_json::from_value::<VerifyRequest>(no_domain).is_err());
        let no_domain = serde_json::json!({ "auth_type": "t-a", "action_hex": "bb" });
        assert!(serde_json::from_value::<ProduceRequest>(no_domain).is_err());
    }

    #[test]
    fn produce_request_ref_serialises_like_the_owned_request() {
        let args = serde_json::json!({ "audience": "a\"b", "nested": [1, null] });
        for args in [Some(&args), None] {
            let owned = ProduceRequest {
                auth_type: "t-a".into(),
                domain: "account-registry".into(),
                action_hex: "0x01".into(),
                args: args.cloned(),
            };
            let borrowed = ProduceRequestRef {
                auth_type: "t-a",
                domain: "account-registry",
                action_hex: "0x01",
                args,
            };
            assert_eq!(
                serde_json::to_string(&borrowed).unwrap(),
                serde_json::to_string(&owned).unwrap()
            );
            assert_eq!(
                serde_json::to_value(borrowed).unwrap(),
                serde_json::to_value(&owned).unwrap()
            );
        }
    }

    #[test]
    fn verify_request_ref_serialises_like_the_owned_request() {
        let config = serde_json::json!({ "allowlist": ["k"], "audience": "é" });
        for (config, peer_id) in [
            (Some(&config), Some("12D3KooW")),
            (Some(&config), None),
            (None, Some("12D3KooW")),
            (None, None),
        ] {
            let owned = VerifyRequest {
                auth_type: "t-a".into(),
                payload_hex: "aa".into(),
                domain: "rln-membership".into(),
                action_hex: "bb".into(),
                config: config.cloned(),
                peer_id: peer_id.map(str::to_owned),
            };
            let borrowed = VerifyRequestRef {
                auth_type: "t-a",
                payload_hex: "aa",
                domain: "rln-membership",
                action_hex: "bb",
                config,
                peer_id,
            };
            assert_eq!(
                serde_json::to_string(&borrowed).unwrap(),
                serde_json::to_string(&owned).unwrap()
            );
            assert_eq!(
                serde_json::to_value(borrowed).unwrap(),
                serde_json::to_value(&owned).unwrap()
            );
        }
    }

    #[test]
    fn nullifiers_are_namespaced_by_scope_and_auth_type() {
        assert_eq!(
            namespaced_nullifier("cfg1", "eth-allowlist", "0xab"),
            "cfg1:eth-allowlist:0xab"
        );
    }
}
