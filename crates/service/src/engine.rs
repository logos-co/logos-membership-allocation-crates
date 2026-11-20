use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use auth_vector::{AuthType, Verdict, VerifyRegistry, VerifyRequest, VerifyRequestRef};
use paymaster_lp::{self as lp, b64, b64_decode};
use paymaster_wire::envelope::{SponsorRequest, SponsorResponse, Status};
use paymaster_wire::service_data;
use serde_json::{json, Value};

use crate::advert::{served_pairs, AdBoard, AdSpec, Advertiser};
use crate::lock;
use crate::nullifiers::NullifierStore;

const ACCEPT_TIMEOUT_MS: i32 = 2_000;
const ACCEPT_IDLE: &str = "timeout waiting for inbound stream";
const ACCEPT_CALL_MARGIN_MS: i32 = 3_000;
const READ_TIMEOUT_MS: i32 = 60_000;
const WRITE_TIMEOUT_MS: i32 = 30_000;
const MOUNT_TIMEOUT_MS: i32 = 30_000;
const AUTH_VERIFY_TIMEOUT_MS: i32 = 30_000;
pub const DEFAULT_CONFIRM_BUDGET_S: u64 = 150;

#[derive(Debug)]
pub enum ExecError {
    NotSubmitted(String),
    Unconfirmed(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Decode,
    Invalid,
    Unconfigured,
    ScopeNotServed,
    AuthTypeNotServed,
    AuthRejected,
    Verifier,
    CredentialUsed,
    Store,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Refusal::Decode => "decode",
            Refusal::Invalid => "invalid",
            Refusal::Unconfigured => "unconfigured",
            Refusal::ScopeNotServed => "scope_not_served",
            Refusal::AuthTypeNotServed => "auth_type_not_served",
            Refusal::AuthRejected => "auth_rejected",
            Refusal::Verifier => "verifier",
            Refusal::CredentialUsed => "credential_used",
            Refusal::Store => "store",
        }
    }
}
pub struct Spend {
    pub uses: u32,
    pub tie: Option<String>,
}

impl Spend {
    pub fn once() -> Self {
        Spend { uses: 1, tie: None }
    }
}

const USE_MARK: char = '#';
const TIE_MARK: char = '@';

fn use_key(base: &str, k: u32) -> Cow<'_, str> {
    if k == 0 {
        Cow::Borrowed(base)
    } else {
        Cow::Owned(format!("{base}{USE_MARK}{k}"))
    }
}

pub struct Denial {
    pub code: Refusal,
    pub message: String,
}

impl Denial {
    pub fn scope(message: String) -> Self {
        Denial {
            code: Refusal::ScopeNotServed,
            message,
        }
    }

    pub fn invalid(message: String) -> Self {
        Denial {
            code: Refusal::Invalid,
            message,
        }
    }
}

pub struct Configured<C> {
    pub cfg: C,
    pub scopes: Vec<String>,
    pub reply: Value,
}

pub trait Service: Send + Sync + 'static {
    type Cfg: Send + Sync + 'static;
    type Body;
    type Job;
    type Grant;

    const NAME: &'static str;
    const CODEC: &'static str;
    const DOMAIN: &'static str;
    const ACTION_KIND: &'static str;
    const MAX_REQUEST_BYTES: u64 = 4096;

    fn configure(&self, args: &Value) -> Result<Configured<Self::Cfg>, String>;
    fn parse(&self, action: &[u8]) -> Result<Self::Body, String>;
    fn precheck(&self, body: &Self::Body) -> Result<(), String>;
    fn admit(
        &self,
        cfg: &Self::Cfg,
        scope: Option<&str>,
        body: &Self::Body,
    ) -> Result<Self::Job, Denial>;
    fn scope<'a>(&self, job: &'a Self::Job) -> &'a str;
    fn spend(&self, _cfg: &Self::Cfg, _body: &Self::Body, _job: &Self::Job) -> Spend {
        Spend::once()
    }
    fn settled(&self, cfg: &Self::Cfg, body: &Self::Body, job: &Self::Job) -> Option<Self::Grant>;
    fn execute(
        &self,
        cfg: &Self::Cfg,
        body: &Self::Body,
        job: &Self::Job,
        confirm_budget_s: u64,
    ) -> Result<Self::Grant, ExecError>;
    fn encode_grant(&self, grant: &Self::Grant) -> Vec<u8>;
}

struct Served<C> {
    service: C,
    confirm_budget_s: u64,
    auth_verifiers: HashMap<String, (Option<String>, Option<Value>)>,
}

pub struct ServeState {
    mounted: bool,
    advertiser: Option<Advertiser>,
}

impl Default for ServeState {
    fn default() -> Self {
        ServeState {
            mounted: false,
            advertiser: Some(Advertiser::default()),
        }
    }
}

pub struct Engine<S: Service> {
    service: S,
    vectors: VerifyRegistry,
    served: Mutex<Option<Arc<Served<S::Cfg>>>>,
    nullifiers: Mutex<NullifierStore>,
    ads: AdBoard,
}

fn blob(v: &Value) -> Value {
    json!([v.to_string()])
}

enum Outcome<G> {
    Granted(G),
    Refused(Refusal, String),
    NotSubmitted(String),
    Unconfirmed(String),
}

fn ask_verifier(module: &str, req: &VerifyRequestRef<'_>) -> Result<Verdict, String> {
    let verify_json = serde_json::to_string(req).map_err(|e| format!("verify request: {e}"))?;
    let reply = lp::call_module_json(
        module,
        auth_vector::VERIFY_METHOD,
        &json!([verify_json]),
        AUTH_VERIFY_TIMEOUT_MS,
    )?;
    auth_vector::parse_verdict(&reply)
}

impl<S: Service> Engine<S> {
    pub fn new(service: S) -> Self {
        Self::with_vectors(service, VerifyRegistry::new())
    }

    pub fn with_vectors(service: S, vectors: VerifyRegistry) -> Self {
        Engine {
            service,
            vectors,
            served: Mutex::new(None),
            nullifiers: Mutex::default(),
            ads: AdBoard::default(),
        }
    }

    pub fn service(&self) -> &S {
        &self.service
    }

    pub fn serve(
        self: &Arc<Self>,
        state: &mut ServeState,
        args_json: &str,
    ) -> Result<Value, String> {
        let mut a: Value =
            serde_json::from_str(args_json).map_err(|e| format!("serve args: {e}"))?;
        let Configured {
            cfg,
            scopes,
            mut reply,
        } = self.service.configure(&a)?;
        let confirm_budget_s = match a.get("confirmBudgetSec") {
            None | Some(Value::Null) => DEFAULT_CONFIRM_BUDGET_S,
            Some(v) => v
                .as_u64()
                .filter(|s| *s >= 1)
                .ok_or("confirmBudgetSec must be a positive integer (seconds)")?,
        };
        let advertise_wanted = match a.get("advertise") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(b)) => Some(*b),
            Some(_) => return Err("advertise must be a boolean".into()),
        };
        let advertise_addrs = match a.get("advertiseAddrs") {
            None | Some(Value::Null) => None,
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .map(|v| v.as_str().map(str::to_owned))
                    .collect::<Option<Vec<String>>>()
                    .ok_or("advertiseAddrs must be an array of multiaddr strings")?,
            ),
            Some(_) => return Err("advertiseAddrs must be an array of multiaddr strings".into()),
        };

        let mut auth_verifiers: HashMap<String, (Option<String>, Option<Value>)> = HashMap::new();
        match a.get_mut("authVerifiers").map(Value::take) {
            None | Some(Value::Null) => {}
            Some(Value::Object(map)) => {
                for (atype, mut v) in map {
                    if !v.is_object() {
                        return Err(format!(
                            "authVerifiers['{atype}'] must be an object of {{module?, config?}}"
                        ));
                    }
                    let config = v.get_mut("config").map(Value::take);
                    let module = match v.get_mut("module").map(Value::take) {
                        None | Some(Value::Null) => {
                            let (scheme, authoriser) = AuthType::parse(&atype)
                                .and_then(|t| self.vectors.resolve(&t))
                                .map_err(|e| {
                                    format!("authVerifiers['{atype}'] needs a module: {e}")
                                })?;
                            scheme
                                .config(config.as_ref())
                                .and_then(|_| authoriser.config(scheme, config.as_ref()))
                                .map_err(|e| format!("authVerifiers['{atype}']: {e}"))?;
                            None
                        }
                        Some(Value::String(m)) if !m.is_empty() => {
                            lp::ensure_client(&m)
                                .map_err(|e| format!("authVerifiers['{atype}']: {e}"))?;
                            Some(m)
                        }
                        Some(_) => {
                            return Err(format!(
                                "authVerifiers['{atype}']: module must be a non-empty string"
                            ))
                        }
                    };
                    auth_verifiers.insert(atype, (module, config));
                }
            }
            Some(_) => {
                return Err("authVerifiers must be an object of {type: {module?, config?}}".into())
            }
        }

        let data = match advertise_wanted {
            Some(false) => None,
            _ => Some(service_data(&served_pairs(&scopes, &auth_verifiers))?),
        };

        let nullifiers_path = a
            .get("consumedNullifiersPath")
            .and_then(Value::as_str)
            .unwrap_or("");
        lock(&self.nullifiers)
            .open(nullifiers_path)
            .map_err(|e| format!("nullifier store: {e}"))?;
        *lock(&self.served) = Some(Arc::new(Served {
            service: cfg,
            confirm_budget_s,
            auth_verifiers,
        }));

        reply["mounted"] = json!(true);
        reply["advertised"] = json!(false);
        if let Some(data) = &data {
            reply["serviceId"] = json!(S::CODEC);
            reply["serviceData"] = json!(data);
        }
        let wanted = data.map(|data| AdSpec {
            data,
            addrs: advertise_addrs,
        });
        let Some(advertiser) = state.advertiser.as_mut() else {
            if *lock(&self.ads.placed) == wanted {
                reply["advertised"] = json!(wanted.is_some());
            } else {
                reply["advertisePending"] = json!(true);
            }
            *lock(&self.ads.wanted) = wanted;
            return Ok(reply);
        };
        *lock(&self.ads.wanted) = wanted;
        advertiser.first(&self.ads, S::CODEC, &mut reply, advertise_wanted)?;
        if !state.mounted {
            lp::call_libp2p("mountProtocol", &json!([S::CODEC]), MOUNT_TIMEOUT_MS)
                .map_err(|e| format!("mountProtocol: {e}"))?;
            state.mounted = true;
        }
        if let Some(advertiser) = state.advertiser.take() {
            let engine = Arc::clone(self);
            std::thread::spawn(move || engine.worker_loop(advertiser));
        }
        Ok(reply)
    }

    fn worker_loop(&self, mut advertiser: Advertiser) {
        loop {
            if let Err(e) = advertiser.tick(&self.ads, S::CODEC) {
                eprintln!("{} serve: advertisement: {e}", S::NAME);
            }
            let accept = lp::call_libp2p(
                "protocolAcceptStream",
                &blob(&json!({ "proto": S::CODEC, "timeoutMs": ACCEPT_TIMEOUT_MS })),
                ACCEPT_TIMEOUT_MS + ACCEPT_CALL_MARGIN_MS,
            );
            let stream_id = match &accept {
                Ok(v) => v.get("streamId").and_then(Value::as_u64),
                Err(e) if e.contains(ACCEPT_IDLE) => continue,
                Err(_) => None,
            };
            let Some(stream_id) = stream_id else {
                eprintln!("{} serve: accept had no streamId: {accept:?}", S::NAME);
                continue;
            };
            let peer_id = accept
                .as_ref()
                .ok()
                .and_then(|v| v.get("peerId"))
                .and_then(Value::as_str);
            if let Err(e) = self.handle_stream(stream_id, peer_id) {
                eprintln!("{} serve: stream {stream_id}: {e}", S::NAME);
            }
        }
    }

    fn handle_stream(&self, stream_id: u64, peer_id: Option<&str>) -> Result<(), String> {
        let release = || {
            let _ = lp::call_libp2p(
                "streamReleaseJson",
                &blob(&json!({ "streamId": stream_id })),
                10_000,
            );
        };
        let req_bytes = (|| -> Result<Vec<u8>, String> {
            let read = lp::call_libp2p(
                "streamReadLpJson",
                &blob(&json!({
                    "streamId": stream_id,
                    "maxSize": S::MAX_REQUEST_BYTES,
                    "timeoutMs": READ_TIMEOUT_MS,
                })),
                READ_TIMEOUT_MS + 10_000,
            )?;
            let data_b64 = read
                .get("dataB64")
                .and_then(Value::as_str)
                .ok_or("streamReadLpJson: no dataB64")?;
            b64_decode(data_b64)
        })()
        .inspect_err(|_| release())?;

        let resp = self.handle_request(&req_bytes, peer_id);

        let _ = lp::call_libp2p(
            "streamWriteLpJson",
            &blob(&json!({ "streamId": stream_id, "dataB64": b64(&resp) })),
            WRITE_TIMEOUT_MS + 10_000,
        );
        release();
        Ok(())
    }

    fn release(&self, keys: &[String]) -> String {
        let mut store = lock(&self.nullifiers);
        let mut note = String::new();
        for key in keys {
            if let Err(e) = store.release(key) {
                note = format!("; nullifier store: {e}");
            }
        }
        note
    }

    pub fn handle_request(&self, buf: &[u8], peer_id: Option<&str>) -> Vec<u8> {
        let (request_id, outcome) = match SponsorRequest::decode(buf) {
            Ok(req) => {
                let outcome = self.decide(&req, peer_id);
                (req.request_id, outcome)
            }
            Err(e) => (
                String::new(),
                Outcome::Refused(Refusal::Decode, format!("decode error: {e}")),
            ),
        };
        let (status, message, result, code) = match outcome {
            Outcome::Granted(grant) => (
                Status::Granted,
                None,
                Some(self.service.encode_grant(&grant)),
                None,
            ),
            Outcome::Refused(code, message) => {
                (Status::Refused, Some(message), None, Some(code.code()))
            }
            Outcome::NotSubmitted(message) => (Status::NotSubmitted, Some(message), None, None),
            Outcome::Unconfirmed(message) => (Status::Unconfirmed, Some(message), None, None),
        };
        SponsorResponse {
            request_id,
            status,
            message,
            result,
            code: code.map(str::to_owned),
        }
        .encode()
    }

    fn decide(&self, req: &SponsorRequest, peer_id: Option<&str>) -> Outcome<S::Grant> {
        use Outcome::Refused;
        if req.action_kind != S::ACTION_KIND {
            return Refused(
                Refusal::ScopeNotServed,
                format!("action kind not served: {}", req.action_kind),
            );
        }
        let body = match self.service.parse(&req.action) {
            Ok(b) => b,
            Err(why) => return Refused(Refusal::Invalid, why),
        };
        if let Err(why) = self.service.precheck(&body) {
            return Refused(Refusal::Invalid, why);
        }

        let Some(served) = lock(&self.served).as_ref().map(Arc::clone) else {
            return Refused(Refusal::Unconfigured, "service not configured".to_owned());
        };
        let cfg = &served.service;

        let job = match self.service.admit(cfg, req.scope.as_deref(), &body) {
            Ok(j) => j,
            Err(d) => return Refused(d.code, d.message),
        };

        let auth_type = String::from_utf8_lossy(&req.authentication_type);
        let mut reserved: Vec<String> = Vec::new();

        if !served.auth_verifiers.is_empty() {
            let Some((module, verifier_config)) = served.auth_verifiers.get(auth_type.as_ref())
            else {
                return Refused(
                    Refusal::AuthTypeNotServed,
                    format!("unsupported authentication_type: '{auth_type}'"),
                );
            };
            let verifier = || match module {
                Some(module) => format!("auth verifier {module}"),
                None => format!("auth vector {auth_type}"),
            };
            let payload_hex = hex::encode(&req.authentication_payload);
            let action_hex = hex::encode(req.action_digest());
            let verdict = match module {
                Some(module) => ask_verifier(
                    module,
                    &VerifyRequestRef {
                        auth_type: &auth_type,
                        payload_hex: &payload_hex,
                        domain: S::DOMAIN,
                        action_hex: &action_hex,
                        config: verifier_config.as_ref(),
                        peer_id,
                    },
                ),
                None => auth_vector::verify_flow(
                    &self.vectors,
                    &VerifyRequest {
                        auth_type: auth_type.to_string(),
                        payload_hex,
                        domain: S::DOMAIN.to_owned(),
                        action_hex,
                        config: verifier_config.clone(),
                        peer_id: peer_id.map(str::to_owned),
                    },
                ),
            };
            let verdict = match verdict {
                Ok(v) => v,
                Err(e) => return Refused(Refusal::Verifier, format!("{}: {e}", verifier())),
            };
            if !verdict.ok {
                let reason = verdict
                    .reason
                    .unwrap_or_else(|| "verifier rejected the request".to_owned());
                return Refused(Refusal::AuthRejected, reason);
            }
            if let Some(nul) = verdict.nullifier {
                let nul = nul.trim().to_lowercase();
                if nul.is_empty()
                    || nul.chars().any(|c| {
                        c.is_whitespace() || c.is_control() || c == USE_MARK || c == TIE_MARK
                    })
                {
                    return Refused(
                        Refusal::Verifier,
                        format!("{}: malformed nullifier", verifier()),
                    );
                }
                let base =
                    auth_vector::namespaced_nullifier(self.service.scope(&job), &auth_type, &nul);
                let spend = self.service.spend(cfg, &body, &job);
                let tie_prefix = format!("{base}{TIE_MARK}");
                let (used, free, tied) = {
                    let store = lock(&self.nullifiers);
                    let mut used = 0u32;
                    let mut free = None;
                    for k in 0..spend.uses.max(1) {
                        let key = use_key(&base, k);
                        if store.is_spent(&key) {
                            used += 1;
                        } else if free.is_none() {
                            free = Some(key.into_owned());
                        }
                    }
                    (used, free, store.suffix_of(&tie_prefix).map(str::to_owned))
                };
                if let (Some(want), Some(tied)) = (&spend.tie, &tied) {
                    if tied != want {
                        return Refused(
                            Refusal::CredentialUsed,
                            format!("credential already used for {tied}: {base}"),
                        );
                    }
                }
                if used > 0 {
                    if let Some(grant) = self.service.settled(cfg, &body, &job) {
                        return Outcome::Granted(grant);
                    }
                }
                let Some(key) = free else {
                    return Refused(
                        Refusal::CredentialUsed,
                        format!("credential already used: {base}"),
                    );
                };
                let tie_key = match (spend.tie, tied) {
                    (Some(want), None) => Some(format!("{tie_prefix}{want}")),
                    _ => None,
                };
                for key in std::iter::once(key).chain(tie_key) {
                    let outcome = lock(&self.nullifiers).reserve(&key);
                    let refusal = match outcome {
                        Ok(true) => {
                            reserved.push(key);
                            continue;
                        }
                        Ok(false) => Refused(
                            Refusal::CredentialUsed,
                            format!("credential already used: {base}"),
                        ),
                        Err(e) => Refused(Refusal::Store, format!("nullifier store: {e}")),
                    };
                    self.release(&reserved);
                    return refusal;
                }
            }
        }

        match self
            .service
            .execute(cfg, &body, &job, served.confirm_budget_s)
        {
            Ok(grant) => Outcome::Granted(grant),
            Err(ExecError::NotSubmitted(why)) => {
                let store_note = self.release(&reserved);
                Outcome::NotSubmitted(format!("{why}{store_note}"))
            }
            Err(ExecError::Unconfirmed(why)) => Outcome::Unconfirmed(why),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::advert::tests::{ad_calls, placed, scripted_libp2p, spec};

    const SCOPE: &str = "s1";

    struct Toy;

    impl Service for Toy {
        type Cfg = String;
        type Body = String;
        type Job = String;
        type Grant = Value;

        const NAME: &'static str = "toy";
        const CODEC: &'static str = "/test/toy/1.0.0";
        const DOMAIN: &'static str = "toy";
        const ACTION_KIND: &'static str = "toy/do";

        fn configure(&self, args: &Value) -> Result<Configured<String>, String> {
            let scope = args
                .get("scope")
                .and_then(Value::as_str)
                .ok_or("missing scope")?;
            Ok(Configured {
                cfg: scope.to_string(),
                scopes: vec![scope.to_string()],
                reply: json!({ "scopes": [scope] }),
            })
        }

        fn parse(&self, action: &[u8]) -> Result<String, String> {
            String::from_utf8(action.to_vec()).map_err(|e| format!("action: {e}"))
        }

        fn precheck(&self, what: &String) -> Result<(), String> {
            if what.is_empty() {
                return Err("nothing asked".into());
            }
            Ok(())
        }

        fn admit(&self, cfg: &String, scope: Option<&str>, _: &String) -> Result<String, Denial> {
            if scope.is_some_and(|s| s != cfg) {
                return Err(Denial::scope("scope not served".into()));
            }
            Ok(cfg.to_owned())
        }

        fn scope<'a>(&self, job: &'a String) -> &'a str {
            job
        }

        fn spend(&self, _: &String, what: &String, _: &String) -> Spend {
            match what.strip_prefix("acct:") {
                Some(account) => Spend {
                    uses: 3,
                    tie: Some(account.split('/').next().unwrap_or("").to_string()),
                },
                None => Spend::once(),
            }
        }

        fn settled(&self, _: &String, what: &String, _: &String) -> Option<Value> {
            (what == "done-before").then(|| json!("settled"))
        }

        fn execute(
            &self,
            _: &String,
            what: &String,
            _: &String,
            confirm_budget_s: u64,
        ) -> Result<Value, ExecError> {
            let reply = lp::call_module_json_classified(
                "toy_chain",
                "submit",
                &json!([what, confirm_budget_s]),
                1_000,
            )
            .map_err(|e| ExecError::Unconfirmed(e.into_message()))?;
            match reply.get("error").and_then(Value::as_str) {
                Some(why) => Err(ExecError::NotSubmitted(why.to_string())),
                None => Ok(reply),
            }
        }

        fn encode_grant(&self, grant: &Value) -> Vec<u8> {
            grant.to_string().into_bytes()
        }
    }

    fn request(id: &str, auth_type: &str, what: &str) -> SponsorRequest {
        SponsorRequest {
            request_id: id.into(),
            authentication_type: auth_type.as_bytes().to_vec(),
            authentication_payload: Vec::new(),
            action_kind: Toy::ACTION_KIND.into(),
            action: what.as_bytes().to_vec(),
            scope: None,
        }
    }

    fn engine() -> Arc<Engine<Toy>> {
        Arc::new(Engine::new(Toy))
    }

    fn serve(e: &Arc<Engine<Toy>>, args: &Value) -> Result<Value, String> {
        e.serve(&mut ServeState::default(), &args.to_string())
    }

    fn send(e: &Engine<Toy>, req: &SponsorRequest) -> SponsorResponse {
        SponsorResponse::decode(&e.handle_request(&req.encode(), Some("peer"))).unwrap()
    }

    fn ask(e: &Engine<Toy>, id: &str, auth_type: &str, what: &str) -> SponsorResponse {
        send(e, &request(id, auth_type, what))
    }

    fn grant(resp: &SponsorResponse) -> Value {
        assert_eq!(resp.status, Status::Granted, "{resp:?}");
        serde_json::from_slice(resp.result.as_deref().unwrap()).unwrap()
    }

    fn refusal(resp: &SponsorResponse) -> (&str, &str) {
        assert_eq!(resp.status, Status::Refused, "{resp:?}");
        assert_eq!(resp.result, None);
        (
            resp.code.as_deref().unwrap_or(""),
            resp.message.as_deref().unwrap_or(""),
        )
    }

    fn tmp(name: &str) -> String {
        let p =
            std::env::temp_dir().join(format!("paymaster-engine-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    fn vector_engine(store: &str) -> Arc<Engine<Toy>> {
        let e = engine();
        let args = json!({
            "scope": SCOPE,
            "advertise": false,
            "consumedNullifiersPath": store,
            "authVerifiers": { "t": { "module": "verifier_module", "config": { "k": 1 } } },
        });
        assert_eq!(
            serve(&e, &args).unwrap_err(),
            "mountProtocol: refused in test"
        );
        e
    }

    #[test]
    fn advertise_addrs_place_a_record_signed_for_them() {
        scripted_libp2p(|| 1);
        let addrs = ["/ip4/203.0.113.7/tcp/4001"];
        let e = serve(
            &engine(),
            &json!({ "scope": SCOPE, "advertiseAddrs": addrs }),
        )
        .unwrap_err();
        assert_eq!(e, "mountProtocol: refused in test");
        let data = service_data(&[(SCOPE, "")]).unwrap();
        let b64url = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            data.as_bytes(),
        );
        assert_eq!(
            ad_calls(),
            [
                (
                    "createXpr".to_string(),
                    json!([addrs, { Toy::CODEC: { "_bytes": b64url } }, lp::fake::START_S])
                ),
                (
                    "discoStartAdvertising".to_string(),
                    json!([Toy::CODEC, data, "XPRB64"])
                ),
                ("mountProtocol".to_string(), json!([Toy::CODEC])),
            ]
        );
        assert_eq!(lp::fake::methods()[0], "connectedPeers");
        let e = serve(&engine(), &json!({ "scope": SCOPE, "advertiseAddrs": [7] })).unwrap_err();
        assert!(e.contains("advertiseAddrs must be an array"), "got: {e}");

        scripted_libp2p(|| 1);
        let _ = serve(&engine(), &json!({ "scope": SCOPE }));
        assert_eq!(
            ad_calls()[0],
            (
                "discoStartAdvertising".to_string(),
                json!([Toy::CODEC, data, ""])
            )
        );
        lp::fake::clear();
    }

    #[test]
    fn serve_validates_its_own_arguments() {
        let e = engine();
        for (args, needle) in [
            (json!({}), "missing scope"),
            (
                json!({ "scope": SCOPE, "advertise": "yes" }),
                "advertise must be a boolean",
            ),
            (
                json!({ "scope": SCOPE, "confirmBudgetSec": 0 }),
                "confirmBudgetSec must be a positive integer",
            ),
            (
                json!({ "scope": SCOPE, "authVerifiers": "oops" }),
                "must be an object",
            ),
            (
                json!({ "scope": SCOPE, "authVerifiers": { "t": "oops" } }),
                "authVerifiers['t'] must be an object",
            ),
            (
                json!({ "scope": SCOPE, "authVerifiers": { "t": {} } }),
                "needs a module",
            ),
            (
                json!({ "scope": SCOPE, "authVerifiers": { "peer-any": {} } }),
                "authVerifiers['peer-any'] needs a module: unknown auth_type 'peer-any'",
            ),
            (
                json!({ "scope": SCOPE, "authVerifiers": { "t": { "module": 7 } } }),
                "module must be a non-empty string",
            ),
            (
                json!({ "scope": SCOPE, "authVerifiers": { "t": { "module": "nope_module" } } }),
                "authVerifiers['t']",
            ),
        ] {
            let err = serve(&e, &args).unwrap_err();
            assert!(err.contains(needle), "{args}: {err}");
        }
    }

    #[test]
    fn a_re_serve_while_the_worker_serves_calls_no_libp2p_and_waits_for_nothing() {
        let e = engine();
        let args = json!({ "scope": SCOPE }).to_string();
        let wish = spec(&service_data(&[(SCOPE, "")]).unwrap());

        *lock(&e.ads.wanted) = Some(spec("mid"));
        *lock(&e.ads.placed) = Some(spec("old"));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let worker_engine = Arc::clone(&e);
        let worker = std::thread::spawn(move || {
            lp::fake::install(Box::new(move |_, m, _| {
                if m == "discoStopAdvertising" {
                    let _ = entered_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(5));
                }
                Ok(json!(true))
            }));
            let mut adv = placed(spec("old"), 1);
            let placed = adv.reconcile(&worker_engine.ads, Toy::CODEC, false, 1);
            (adv, placed)
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the worker is inside its libp2p call");

        let mut state = ServeState {
            mounted: true,
            advertiser: None,
        };
        lp::fake::install(Box::new(|_, m, _| Err(format!("unscripted {m}"))));
        let t = Instant::now();
        let reply = e.serve(&mut state, &args).unwrap();
        let waited = t.elapsed();
        let _ = release_tx.send(());
        let (mut adv, placed) = worker.join().unwrap();
        assert!(
            waited < Duration::from_secs(1),
            "serve waited {waited:?} on the worker"
        );
        assert!(lp::fake::calls().is_empty(), "{:?}", lp::fake::methods());
        assert_eq!(reply["advertisePending"], json!(true));
        assert_eq!(reply["advertised"], json!(false));
        assert_eq!(reply["scopes"], json!([SCOPE]));

        placed.unwrap();
        assert_eq!(*lock(&e.ads.placed), Some(spec("mid")));
        scripted_libp2p(|| 1);
        adv.tick(&e.ads, Toy::CODEC).unwrap();
        assert_eq!(*lock(&e.ads.placed), Some(wish));

        lp::fake::install(Box::new(|_, m, _| Err(format!("unscripted {m}"))));
        let reply = e.serve(&mut state, &args).unwrap();
        assert!(lp::fake::calls().is_empty(), "{:?}", lp::fake::methods());
        assert_eq!(reply["advertised"], json!(true));
        assert_eq!(reply.get("advertisePending"), None);
        lp::fake::clear();
    }

    #[test]
    fn a_request_is_refused_before_any_verifier_or_chain_call() {
        let e = engine();
        lp::fake::install(Box::new(|_, m, _| Err(format!("unscripted {m}"))));

        let undecodable = SponsorResponse::decode(&e.handle_request(&[0xff], None)).unwrap();
        assert_eq!(undecodable.request_id, "");
        let (code, why) = refusal(&undecodable);
        assert_eq!(code, "decode");
        assert!(why.starts_with("decode error: "), "{why}");

        let unconfigured = ask(&e, "r", "", "x");
        assert_eq!(unconfigured.request_id, "r");
        assert_eq!(
            refusal(&unconfigured),
            ("unconfigured", "service not configured")
        );

        let _ = serve(&e, &json!({ "scope": SCOPE, "advertise": false }));
        assert_eq!(refusal(&ask(&e, "r", "", "")), ("invalid", "nothing asked"));
        let mut not_text = request("r", "", "x");
        not_text.action = vec![0xff];
        assert_eq!(refusal(&send(&e, &not_text)).0, "invalid");
        let mut other_kind = request("r", "", "x");
        other_kind.action_kind = "other/kind".into();
        assert_eq!(
            refusal(&send(&e, &other_kind)),
            ("scope_not_served", "action kind not served: other/kind")
        );
        let mut elsewhere = request("r", "", "x");
        elsewhere.scope = Some("s2".into());
        assert_eq!(
            refusal(&send(&e, &elsewhere)),
            ("scope_not_served", "scope not served")
        );
        assert_eq!(lp::fake::methods(), ["mountProtocol"]);
        lp::fake::clear();
    }

    #[test]
    fn an_open_provider_executes_without_a_verifier() {
        let e = engine();
        lp::fake::install(Box::new(|_, m, a| match m {
            "submit" => Ok(json!({ "did": a[0], "budget": a[1] })),
            m => Err(format!("unscripted {m}")),
        }));
        let _ = serve(
            &e,
            &json!({ "scope": SCOPE, "advertise": false, "confirmBudgetSec": 7 }),
        );
        let mut named = request("r", "", "x");
        named.scope = Some(SCOPE.into());
        let resp = send(&e, &named);
        assert_eq!(grant(&resp), json!({ "did": "x", "budget": 7 }));
        assert_eq!((resp.message, resp.code), (None, None));
        assert_eq!(lp::fake::methods(), ["mountProtocol", "submit"]);
        lp::fake::clear();
    }

    const PEER: &str = "12D3KooWA1yXQfKD3c8QznGkpf1ZepPH1FQKwAwMxbTh1feQsapZ";
    const OTHER_PEER: &str = "16Uiu2HAkyiMKmjcAj4FS5jot1jMZB73mnY3wJnSTKZmTBhrFJEaT";

    fn peer_engine() -> Arc<Engine<Toy>> {
        Arc::new(Engine::with_vectors(
            Toy,
            VerifyRegistry::new()
                .scheme(auth_vectors::scheme::Peer)
                .authoriser(auth_vectors::authoriser::Any)
                .authoriser(auth_vectors::authoriser::Allowlist),
        ))
    }

    #[test]
    fn a_vector_of_the_engines_own_is_verified_without_a_module() {
        let store = tmp("own");
        lp::fake::install(Box::new(|_, m, _| match m {
            "submit" => Ok(json!({ "landed": true })),
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        let e = peer_engine();
        let args = json!({
            "scope": SCOPE,
            "advertise": false,
            "consumedNullifiersPath": store,
            "authVerifiers": {
                "peer-any": {},
                "peer-allowlist": { "config": { "allowlist": [PEER] } },
            },
        });
        assert_eq!(
            serve(&e, &args).unwrap_err(),
            "mountProtocol: refused in test"
        );
        let from = |id: &str, auth_type: &str, peer: &str| {
            let frame = e.handle_request(&request(id, auth_type, "x").encode(), Some(peer));
            SponsorResponse::decode(&frame).unwrap()
        };
        assert_eq!(
            grant(&from("r1", "peer-any", PEER)),
            json!({ "landed": true })
        );
        assert_eq!(refusal(&from("r2", "peer-any", PEER)).0, "credential_used");
        assert_eq!(
            grant(&from("r3", "peer-allowlist", PEER)),
            json!({ "landed": true })
        );
        let off_the_list = from("r4", "peer-allowlist", OTHER_PEER);
        let (code, why) = refusal(&off_the_list);
        assert_eq!(code, "auth_rejected");
        assert!(why.starts_with("peer not allowlisted: "), "{why}");
        let no_peer = e.handle_request(&request("r5", "peer-any", "x").encode(), None);
        let no_peer = SponsorResponse::decode(&no_peer).unwrap();
        let (code, why) = refusal(&no_peer);
        assert_eq!(code, "verifier");
        assert!(why.starts_with("auth vector peer-any: "), "{why}");
        assert_eq!(lp::fake::methods(), ["mountProtocol", "submit", "submit"]);
        lp::fake::clear();
        let _ = std::fs::remove_file(&store);
    }

    #[test]
    fn serve_refuses_an_own_vector_it_cannot_answer_or_configure() {
        let e = peer_engine();
        for (verifiers, needle) in [
            (
                json!({ "eth-any": {} }),
                "authVerifiers['eth-any'] needs a module: unknown auth_type 'eth-any'",
            ),
            (
                json!({ "peer-allowlist": {} }),
                "authVerifiers['peer-allowlist']: config.allowlist",
            ),
            (
                json!({ "peer-allowlist": { "config": { "allowlist": ["nobody"] } } }),
                "authVerifiers['peer-allowlist']: peer id 'nobody'",
            ),
        ] {
            let args = json!({ "scope": SCOPE, "advertise": false, "authVerifiers": verifiers });
            let err = serve(&e, &args).unwrap_err();
            assert!(err.contains(needle), "{args}: {err}");
        }
    }

    #[test]
    fn the_verifier_judges_the_services_domain_and_the_requests_digest() {
        let store = tmp("verify");
        let digest = hex::encode(request("r", "t", "x").action_digest());
        lp::fake::install(Box::new(move |target, m, a| match m {
            auth_vector::VERIFY_METHOD => {
                assert_eq!(target, "verifier_module");
                let req: Value = serde_json::from_str(a[0].as_str().unwrap()).unwrap();
                assert_eq!(req["auth_type"], "t");
                assert_eq!(req["domain"], "toy");
                assert_eq!(req["action_hex"], digest);
                assert_eq!(req["payload_hex"], "");
                assert_eq!(req["config"], json!({ "k": 1 }));
                assert_eq!(req["peer_id"], "peer");
                Ok(json!({ "ok": false, "reason": "not on the list" }))
            }
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        let e = vector_engine(&store);
        assert_eq!(
            refusal(&ask(&e, "r", "t", "x")),
            ("auth_rejected", "not on the list")
        );
        assert_eq!(
            refusal(&ask(&e, "r", "other", "x")),
            (
                "auth_type_not_served",
                "unsupported authentication_type: 'other'"
            )
        );
        lp::fake::clear();
        let _ = std::fs::remove_file(&store);
    }

    #[test]
    fn a_credential_is_spent_once_per_scope_and_vector() {
        let store = tmp("spend");
        lp::fake::install(Box::new(|_, m, _| match m {
            auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": " AA " })),
            "submit" => Ok(json!({ "landed": true })),
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        let e = vector_engine(&store);
        assert_eq!(grant(&ask(&e, "r1", "t", "x")), json!({ "landed": true }));
        let nul = auth_vector::namespaced_nullifier(SCOPE, "t", "aa");
        assert!(crate::nullifiers::load_nullifiers(&store)
            .unwrap()
            .contains(&nul));
        assert_eq!(
            refusal(&ask(&e, "r2", "t", "y")),
            (
                "credential_used",
                format!("credential already used: {nul}").as_str()
            )
        );
        assert_eq!(grant(&ask(&e, "r3", "t", "done-before")), "settled");
        assert_eq!(
            lp::fake::methods()
                .iter()
                .filter(|m| *m == "submit")
                .count(),
            1
        );
        lp::fake::clear();
        let _ = std::fs::remove_file(&store);
    }

    #[test]
    fn a_reservation_is_released_only_when_nothing_was_submitted() {
        let store = tmp("release");
        lp::fake::install(Box::new(|_, m, a| match m {
            auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "bb" })),
            "submit" if a[0] == "full" => Ok(json!({ "error": "the registry is full" })),
            "submit" => Err("submit: no answer".into()),
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        let e = vector_engine(&store);
        let nul = auth_vector::namespaced_nullifier(SCOPE, "t", "bb");
        let spent = || {
            crate::nullifiers::load_nullifiers(&store)
                .unwrap()
                .contains(&nul)
        };

        let full = ask(&e, "r1", "t", "full");
        assert_eq!(full.status, Status::NotSubmitted);
        assert_eq!(full.message.as_deref(), Some("the registry is full"));
        assert_eq!(full.code, None);
        assert!(!spent());
        assert_eq!(ask(&e, "r2", "t", "full").status, Status::NotSubmitted);

        let lost = ask(&e, "r3", "t", "lost");
        assert_eq!(lost.status, Status::Unconfirmed, "{lost:?}");
        assert!(spent());
        assert_eq!(refusal(&ask(&e, "r4", "t", "lost")).0, "credential_used");
        lp::fake::clear();
        let _ = std::fs::remove_file(&store);
    }

    #[test]
    fn a_credential_with_several_uses_stays_with_its_first_account() {
        let store = tmp("uses");
        lp::fake::install(Box::new(|_, m, a| match m {
            auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "cc" })),
            "submit" if a[0] == "acct:alice/full" => Ok(json!({ "error": "full" })),
            "submit" => Ok(json!({ "landed": a[0] })),
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
        let e = vector_engine(&store);
        let nul = auth_vector::namespaced_nullifier(SCOPE, "t", "cc");
        let lines = || {
            let mut l: Vec<String> = crate::nullifiers::load_nullifiers(&store)
                .unwrap()
                .into_iter()
                .collect();
            l.sort();
            l
        };

        assert_eq!(
            grant(&ask(&e, "r1", "t", "acct:alice/1"))["landed"],
            "acct:alice/1"
        );
        assert_eq!(lines(), [nul.clone(), format!("{nul}@alice")]);
        assert_eq!(
            refusal(&ask(&e, "r2", "t", "acct:bob/1")),
            (
                "credential_used",
                format!("credential already used for alice: {nul}").as_str()
            )
        );
        let full = ask(&e, "r3", "t", "acct:alice/full");
        assert_eq!(
            (full.status, full.message.as_deref()),
            (Status::NotSubmitted, Some("full"))
        );
        assert_eq!(lines(), [nul.clone(), format!("{nul}@alice")]);
        grant(&ask(&e, "r4", "t", "acct:alice/2"));
        grant(&ask(&e, "r5", "t", "acct:alice/3"));
        assert_eq!(
            lines(),
            [
                nul.clone(),
                format!("{nul}#1"),
                format!("{nul}#2"),
                format!("{nul}@alice")
            ]
        );
        assert_eq!(
            refusal(&ask(&e, "r6", "t", "acct:alice/4")),
            (
                "credential_used",
                format!("credential already used: {nul}").as_str()
            )
        );

        lp::fake::install(Box::new(|_, m, _| match m {
            auth_vector::VERIFY_METHOD => Ok(json!({ "ok": true, "nullifier": "cc#1" })),
            m => Err(format!("unscripted {m}")),
        }));
        assert_eq!(
            refusal(&ask(&e, "r7", "t", "x")),
            (
                "verifier",
                "auth verifier verifier_module: malformed nullifier"
            )
        );
        lp::fake::clear();
        let _ = std::fs::remove_file(&store);
    }
}
