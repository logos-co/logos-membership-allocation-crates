use crate::authtype::AuthType;
use crate::binding::{binding_digest, Binding};
use crate::hex::strip_0x;
use crate::pieces::{Outcome, Transport};
use crate::reason;
use crate::registry::{ProduceRegistry, VerifyRegistry};
use crate::types::{ProduceReply, ProduceRequest, Verdict, VerifyRequest};

macro_rules! reject_on {
    ($e:expr) => {
        match $e {
            Outcome::Ok(v) => v,
            Outcome::Reject(r) => return Ok(Verdict::reject(r)),
        }
    };
}

pub fn verify_flow(r: &VerifyRegistry, req: &VerifyRequest) -> Result<Verdict, String> {
    let t = AuthType::parse(&req.auth_type)?;
    let (scheme, auth) = r.resolve(&t)?;
    let scfg = scheme.config(req.config.as_ref())?;
    let cfg = auth.config(scheme, req.config.as_ref())?;
    let b = reject_on!(Binding::for_verify(req, auth.audience(cfg.as_ref()))?);

    let bytes = match hex::decode(strip_0x(&req.payload_hex)) {
        Ok(b) => b,
        Err(e) => return Ok(Verdict::reject(reason::payload_hex(e))),
    };
    let d = reject_on!(scheme.decode(&bytes));
    let (ev, rest) = reject_on!(auth.decode_evidence(d.rest));
    if !rest.is_empty() {
        return Ok(Verdict::reject(reason::trailing_bytes(rest.len())));
    }

    let judged_claim = match (&d.claimed, auth.before_sig()) {
        (Some(claimed), true) => {
            reject_on!(auth.authorise(cfg.as_ref(), claimed.as_ref(), ev.as_ref())?);
            true
        }
        _ => false,
    };

    let digest = binding_digest(&t, &b, &auth.extra(ev.as_ref()));
    let transport = Transport {
        peer_id: req.peer_id.as_deref(),
    };
    let proven = reject_on!(scheme.verify(scfg.as_ref(), &b, &digest, &d, &transport)?);
    let identity = proven.canonical();
    if let Some(claimed) = &d.claimed {
        let c = claimed.canonical();
        if c != identity {
            return Ok(Verdict::reject(reason::identity_mismatch(&c, &identity)));
        }
    }
    if !judged_claim {
        reject_on!(auth.authorise(cfg.as_ref(), proven.as_ref(), ev.as_ref())?);
    }
    let nullifier = auth.nullifier(proven.as_ref(), ev.as_ref());
    Ok(Verdict::accept(identity, scheme.name(), Some(nullifier)))
}

pub fn produce_flow(r: &ProduceRegistry, req: &ProduceRequest) -> Result<ProduceReply, String> {
    let t = AuthType::parse(&req.auth_type)?;
    let (signer, claimant) = r.resolve(&t)?;
    let b = Binding::from_produce(req)?;
    let evidence = claimant.gather(&b, req.args.as_ref())?;
    let digest = binding_digest(&t, &b, &claimant.extra(&evidence));
    let mut payload = signer.sign(&b, &digest, req.args.as_ref())?;
    payload.extend_from_slice(&evidence);
    Ok(ProduceReply {
        payload_hex: hex::encode(payload),
    })
}

#[cfg(test)]
mod tests {
    use std::any::Any;

    use serde_json::{json, Value};

    use super::*;
    use crate::pieces::{
        Authoriser, Cfg, Check, Claimant, Decoded, Evidence, Identity, Scheme, Signer, Transport,
    };
    use crate::registry::{dispatch_produce, dispatch_verify};

    struct ToyId(String);
    impl Identity for ToyId {
        fn canonical(&self) -> String {
            self.0.clone()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct Toy(&'static str);
    impl Scheme for Toy {
        fn name(&self) -> &'static str {
            self.0
        }
        fn parse_identity(&self, s: &str) -> Result<String, String> {
            crate::norm_hex32("config.allowlist entry", s)
        }
        fn decode<'a>(&self, body: &'a [u8]) -> Outcome<Decoded<'a>> {
            if body.len() < 33 {
                return Outcome::Reject(format!("toy part must be 33 bytes, got {}", body.len()));
            }
            let (part, rest) = body.split_at(33);
            Outcome::Ok(Decoded {
                claimed: Some(Box::new(ToyId(hex::encode(&part[..32])))),
                part,
                rest,
            })
        }
        fn verify(
            &self,
            _cfg: &dyn Any,
            _b: &Binding,
            digest: &[u8; 32],
            d: &Decoded<'_>,
            _t: &Transport<'_>,
        ) -> Check<Box<dyn Identity>> {
            if d.part[32] != digest[0] {
                return Ok(Outcome::Reject(reason::SIG_FAILED.into()));
            }
            Ok(Outcome::Ok(Box::new(ToyId(hex::encode(&d.part[..32])))))
        }
    }

    struct ToySigner(&'static str, [u8; 32]);
    impl Signer for ToySigner {
        fn scheme(&self) -> &'static str {
            self.0
        }
        fn sign(
            &self,
            _b: &Binding,
            digest: &[u8; 32],
            _args: Option<&Value>,
        ) -> Result<Vec<u8>, String> {
            let mut v = self.1.to_vec();
            v.push(digest[0]);
            Ok(v)
        }
        fn identity(&self, _args: Option<&Value>) -> Result<Box<dyn Identity>, String> {
            Ok(Box::new(ToyId(hex::encode(self.1))))
        }
    }

    struct List;
    struct ListCfg(Vec<String>, String);
    impl Authoriser for List {
        fn name(&self) -> &'static str {
            "list"
        }
        fn accepts(&self, _scheme: &str) -> bool {
            true
        }
        fn config(&self, scheme: &dyn Scheme, raw: Option<&Value>) -> Result<Cfg, String> {
            let entries = raw
                .and_then(|c| c.get("allowlist"))
                .and_then(Value::as_array)
                .ok_or_else(|| reason::allowlist_required("toy ids"))?;
            let list = entries
                .iter()
                .map(|e| {
                    e.as_str()
                        .ok_or(reason::ENTRIES_NOT_STRINGS.to_string())
                        .and_then(|s| scheme.parse_identity(s))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let aud = raw
                .and_then(|c| c.get("audience"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            Ok(Box::new(ListCfg(list, aud)))
        }
        fn audience<'a>(&self, cfg: &'a dyn Any) -> &'a str {
            &cfg.downcast_ref::<ListCfg>().unwrap().1
        }
        fn decode_evidence<'a>(&self, rest: &'a [u8]) -> Outcome<(Evidence, &'a [u8])> {
            Outcome::Ok((Box::new(()), rest))
        }
        fn extra(&self, _ev: &dyn Any) -> Vec<u8> {
            Vec::new()
        }
        fn before_sig(&self) -> bool {
            true
        }
        fn authorise(&self, cfg: &dyn Any, id: &dyn Identity, _ev: &dyn Any) -> Check<()> {
            let cfg = cfg.downcast_ref::<ListCfg>().unwrap();
            if cfg.0.contains(&id.canonical()) {
                Ok(Outcome::Ok(()))
            } else {
                Ok(Outcome::Reject(reason::not_allowlisted(
                    "toy id",
                    &id.canonical(),
                )))
            }
        }
    }
    struct NoClaim(&'static str);
    impl Claimant for NoClaim {
        fn authoriser(&self) -> &'static str {
            self.0
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

    struct Stamp;
    impl Authoriser for Stamp {
        fn name(&self) -> &'static str {
            "stamp"
        }
        fn accepts(&self, scheme: &str) -> bool {
            scheme == "toy"
        }
        fn config(&self, _scheme: &dyn Scheme, raw: Option<&Value>) -> Result<Cfg, String> {
            if raw.and_then(|c| c.get("broken")).is_some() {
                return Err("config.broken: operator mistake".into());
            }
            Ok(Box::new(()))
        }
        fn audience<'a>(&self, _cfg: &'a dyn Any) -> &'a str {
            "stamped"
        }
        fn decode_evidence<'a>(&self, rest: &'a [u8]) -> Outcome<(Evidence, &'a [u8])> {
            if rest.len() < 4 {
                return Outcome::Reject("stamp evidence must be 4 bytes".into());
            }
            let (ev, rest) = rest.split_at(4);
            Outcome::Ok((Box::new(ev.to_vec()), rest))
        }
        fn extra(&self, ev: &dyn Any) -> Vec<u8> {
            ev.downcast_ref::<Vec<u8>>().unwrap().clone()
        }
        fn authorise(&self, _cfg: &dyn Any, _id: &dyn Identity, ev: &dyn Any) -> Check<()> {
            if ev.downcast_ref::<Vec<u8>>().unwrap() == b"stmp" {
                Ok(Outcome::Ok(()))
            } else {
                Ok(Outcome::Reject("bad stamp".into()))
            }
        }
        fn nullifier(&self, id: &dyn Identity, _ev: &dyn Any) -> String {
            format!("{}:stamped", id.canonical())
        }
    }
    struct StampClaim;
    impl Claimant for StampClaim {
        fn authoriser(&self) -> &'static str {
            "stamp"
        }
        fn accepts(&self, scheme: &str) -> bool {
            scheme == "toy"
        }
        fn gather(&self, _b: &Binding, args: Option<&Value>) -> Result<Vec<u8>, String> {
            Ok(args
                .and_then(|a| a.get("stamp"))
                .and_then(Value::as_str)
                .unwrap_or("stmp")
                .as_bytes()
                .to_vec())
        }
        fn extra(&self, evidence: &[u8]) -> Vec<u8> {
            evidence.to_vec()
        }
    }

    const KEY: [u8; 32] = [0x42; 32];
    const DOMAIN: &str = "rln-membership";
    const OTHER_DOMAIN: &str = "account-registry";
    fn action() -> String {
        "11".repeat(32)
    }
    fn verify_registry() -> VerifyRegistry {
        VerifyRegistry::new()
            .scheme(Toy("toy"))
            .scheme(Toy("alt"))
            .authoriser(List)
            .authoriser(Stamp)
    }
    fn produce_registry() -> ProduceRegistry {
        ProduceRegistry::new()
            .signer(ToySigner("toy", KEY))
            .signer(ToySigner("alt", KEY))
            .claimant(NoClaim("list"))
            .claimant(StampClaim)
    }
    fn produce_raw(req: &Value) -> Value {
        serde_json::from_str(&dispatch_produce(&req.to_string(), &produce_registry())).unwrap()
    }
    fn produce_in(auth_type: &str, domain: &str, action_hex: &str, args: &Value) -> String {
        let out = produce_raw(
            &json!({ "auth_type": auth_type, "domain": domain, "action_hex": action_hex, "args": args }),
        );
        out["payload_hex"]
            .as_str()
            .unwrap_or_else(|| panic!("{out}"))
            .to_string()
    }
    fn produce(auth_type: &str, args: &Value) -> String {
        produce_in(auth_type, DOMAIN, &action(), args)
    }
    fn verify_in(
        auth_type: &str,
        payload_hex: &str,
        domain: &str,
        action_hex: &str,
        config: &Value,
    ) -> Value {
        let req = json!({
            "auth_type": auth_type, "payload_hex": payload_hex,
            "domain": domain, "action_hex": action_hex, "config": config
        });
        serde_json::from_str(&dispatch_verify(&req.to_string(), &verify_registry())).unwrap()
    }
    fn verify(auth_type: &str, payload_hex: &str, config: &Value) -> Value {
        verify_in(auth_type, payload_hex, DOMAIN, &action(), config)
    }
    fn listed() -> Value {
        json!({ "allowlist": [hex::encode(KEY)] })
    }

    #[test]
    fn registries_list_only_the_compositions_that_exist() {
        assert_eq!(
            verify_registry().auth_types(),
            ["toy-list", "toy-stamp", "alt-list"]
        );
        assert_eq!(
            produce_registry().auth_types(),
            ["toy-list", "toy-stamp", "alt-list"]
        );
    }

    #[test]
    fn produce_then_verify_round_trips_both_authorisers() {
        let p = produce("toy-list", &json!({}));
        let v = verify("toy-list", &p, &listed());
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["nullifier"], hex::encode(KEY));

        let p = produce("toy-stamp", &json!({ "audience": "stamped" }));
        let v = verify("toy-stamp", &format!("0x{p}"), &json!({}));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["nullifier"], format!("{}:stamped", hex::encode(KEY)));
        let p = produce("alt-list", &json!({}));
        assert_eq!(verify("alt-list", &p, &listed())["ok"], true);
    }

    #[test]
    fn refused_and_unknown_compositions_use_the_error_envelope() {
        let req = json!({ "auth_type": "alt-stamp", "payload_hex": "", "domain": DOMAIN, "action_hex": action() });
        let out: Value =
            serde_json::from_str(&dispatch_verify(&req.to_string(), &verify_registry())).unwrap();
        assert!(
            out["error"]
                .as_str()
                .unwrap()
                .contains("does not accept the alt scheme"),
            "{out}"
        );
        let req = json!({ "auth_type": "nope-list", "payload_hex": "", "domain": DOMAIN, "action_hex": action() });
        let out: Value =
            serde_json::from_str(&dispatch_verify(&req.to_string(), &verify_registry())).unwrap();
        assert!(
            out["error"]
                .as_str()
                .unwrap()
                .contains("unknown auth_type 'nope-list'"),
            "{out}"
        );
        let out = produce_raw(
            &json!({ "auth_type": "alt-stamp", "domain": DOMAIN, "action_hex": action() }),
        );
        assert!(
            out["error"].as_str().unwrap().contains("unknown auth_type"),
            "{out}"
        );
        let out = produce_raw(
            &json!({ "auth_type": "toylist", "domain": DOMAIN, "action_hex": action() }),
        );
        assert!(
            out["error"]
                .as_str()
                .unwrap()
                .contains("<scheme>-<authoriser>"),
            "{out}"
        );
    }

    #[test]
    fn operator_mistakes_are_errors_requester_mistakes_are_rejects() {
        let p = produce("toy-list", &json!({}));
        let v = verify("toy-list", &p, &json!({}));
        assert!(
            v["error"].as_str().unwrap().contains("config.allowlist"),
            "{v}"
        );
        let v = verify("toy-stamp", &p, &json!({ "broken": 1 }));
        assert!(
            v["error"].as_str().unwrap().contains("operator mistake"),
            "{v}"
        );

        let v = verify("toy-list", "zz", &listed());
        assert!(
            v["reason"].as_str().unwrap().starts_with("payload hex:"),
            "{v}"
        );
        let v = verify("toy-list", "", &listed());
        assert_eq!(v["reason"], "toy part must be 33 bytes, got 0");
        let mut long = hex::decode(&p).unwrap();
        long.push(0);
        let v = verify("toy-list", &hex::encode(&long), &listed());
        assert_eq!(v["reason"], "payload has 1 trailing bytes");
    }

    #[test]
    fn a_payload_is_bound_to_its_domain_and_action() {
        let p = produce("toy-list", &json!({}));
        assert_eq!(verify("toy-list", &p, &listed())["ok"], true);
        let v = verify_in("toy-list", &p, OTHER_DOMAIN, &action(), &listed());
        assert_eq!(v["reason"], reason::SIG_FAILED, "{v}");
        let v = verify_in("toy-list", &p, DOMAIN, &"12".repeat(32), &listed());
        assert_eq!(v["reason"], reason::SIG_FAILED, "{v}");
        let q = produce_in("toy-list", OTHER_DOMAIN, &action(), &json!({}));
        let v = verify_in("toy-list", &q, OTHER_DOMAIN, &action(), &listed());
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(
            verify("toy-list", &q, &listed())["reason"],
            reason::SIG_FAILED
        );
    }

    #[test]
    fn an_invalid_domain_is_refused_on_both_sides() {
        let p = produce("toy-list", &json!({}));
        for bad in ["", "RLN-membership", "rln/membership", &"d".repeat(65)] {
            let out = produce_raw(
                &json!({ "auth_type": "toy-list", "domain": bad, "action_hex": action() }),
            );
            assert_eq!(out["error"], reason::bad_domain(bad), "{out}");
            let v = verify_in("toy-list", &p, bad, &action(), &listed());
            assert_eq!(v["error"], reason::bad_domain(bad), "{v}");
        }
    }

    #[test]
    fn a_wrong_signature_audience_or_evidence_is_rejected() {
        let p = produce("toy-list", &json!({ "audience": "a" }));
        let v = verify(
            "toy-list",
            &p,
            &json!({ "allowlist": [hex::encode(KEY)], "audience": "b" }),
        );
        assert_eq!(v["reason"], reason::SIG_FAILED, "{v}");
        let mut tampered = hex::decode(&p).unwrap();
        tampered[32] ^= 0xff;
        let v = verify(
            "toy-list",
            &hex::encode(&tampered),
            &json!({ "allowlist": [hex::encode(KEY)], "audience": "a" }),
        );
        assert_eq!(v["reason"], reason::SIG_FAILED);

        let p = produce(
            "toy-stamp",
            &json!({ "audience": "stamped", "stamp": "xxxx" }),
        );
        let v = verify("toy-stamp", &p, &json!({}));
        assert_eq!(
            v["reason"], "bad stamp",
            "the evidence verified (it is bound) but is refused"
        );
    }

    #[test]
    fn before_sig_judges_the_claim_first_otherwise_the_proof() {
        let p = produce("toy-list", &json!({}));
        let mut tampered = hex::decode(&p).unwrap();
        tampered[32] ^= 0xff;
        let v = verify(
            "toy-list",
            &hex::encode(&tampered),
            &json!({ "allowlist": ["00".repeat(32)] }),
        );
        assert!(
            v["reason"].as_str().unwrap().contains("not allowlisted"),
            "{v}"
        );
        let p = produce(
            "toy-stamp",
            &json!({ "audience": "stamped", "stamp": "xxxx" }),
        );
        let mut tampered = hex::decode(&p).unwrap();
        tampered[32] ^= 0xff;
        let v = verify("toy-stamp", &hex::encode(&tampered), &json!({}));
        assert_eq!(v["reason"], reason::SIG_FAILED);
    }

    #[test]
    fn produce_errors_name_the_callers_problem() {
        let out = produce_raw(
            &json!({ "auth_type": "toy-list", "domain": DOMAIN, "action_hex": "11".repeat(31) }),
        );
        assert!(
            out["error"].as_str().unwrap().starts_with("action_hex"),
            "{out}"
        );
        let out = produce_raw(
            &json!({ "auth_type": "toy-list", "domain": DOMAIN, "action_hex": action(), "args": { "audience": 7 } }),
        );
        assert!(
            out["error"].as_str().unwrap().starts_with("audience"),
            "{out}"
        );
    }
}
