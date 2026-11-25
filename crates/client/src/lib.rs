use auth_vector::ProduceRequestRef;
use paymaster_lp::{self as lp, b64, b64_decode, now_s, sleep_s};
use paymaster_wire::envelope::{SponsorRequest, SponsorResponse, Status};
use paymaster_wire::service_data_lists;
use serde_json::{json, Value};

const REQUEST_TIMEOUT_MS: i64 = 190_000;
const REQUEST_CALL_TIMEOUT_MS: i32 = 205_000;
const PRODUCE_TIMEOUT_MS: i32 = 120_000;

const LOOKUP_WAITS_S: [u64; 4] = [0, 2, 4, 8];
const DISCO_TIMEOUT_MS: i32 = 30_000;
const NODE_TIMEOUT_MS: i32 = 30_000;

pub const JOIN_WAIT_S: u64 = 20;

pub const NO_BOOTSTRAP_PEER: &str = "no bootstrap peer to look for a provider through";

pub trait ClientAction {
    const CODEC: &'static str;
    const PROVIDER: &'static str = "provider";

    fn grant(&self, result: &[u8], peer_id: &str) -> Result<Value, String>;
}

fn wait_joined() -> Result<usize, String> {
    let deadline = now_s() + JOIN_WAIT_S;
    loop {
        let n = lp::node_outbound_peers()?;
        if n > 0 || now_s() >= deadline {
            return Ok(n);
        }
        sleep_s(1);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub peer_id: String,
    pub addrs: Vec<String>,
}

impl Candidate {
    pub fn json(&self) -> Value {
        json!({ "peerId": self.peer_id, "addrs": self.addrs })
    }
}

pub fn candidates_in(
    reply: &Value,
    service_id: &str,
    scope: &str,
    auth_type: &str,
) -> Vec<Candidate> {
    let mut out = Vec::new();
    for rec in reply.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let Some(peer_id) = rec.get("peerId").and_then(Value::as_str) else {
            continue;
        };
        let listed = rec
            .get("services")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter(|svc| svc.get("id").and_then(Value::as_str) == Some(service_id))
            .filter_map(|svc| svc.get("data").and_then(Value::as_str))
            .filter_map(|d| b64_decode(d).ok())
            .any(|data| service_data_lists(&data, scope, auth_type));
        if !listed {
            continue;
        }
        let addrs: Vec<String> = rec
            .get("addrs")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if addrs.is_empty() || out.iter().any(|c: &Candidate| c.peer_id == peer_id) {
            continue;
        }
        out.push(Candidate {
            peer_id: peer_id.to_string(),
            addrs,
        });
    }
    out
}

#[derive(Debug, PartialEq)]
pub enum Discovery {
    Unavailable(String),
    NotJoined,
    NoneAdvertising,
    Found(Vec<Candidate>),
}

impl Discovery {
    pub fn message(&self, provider: &str, scope: &str, auth_type: &str) -> String {
        match self {
            Discovery::Unavailable(e) => format!("discovery unavailable: {e}"),
            Discovery::NotJoined => format!(
                "discovery not joined: no connected peer after {}s",
                JOIN_WAIT_S
            ),
            Discovery::NoneAdvertising => {
                format!("no {provider} advertises {scope}/{auth_type}")
            }
            Discovery::Found(_) => String::new(),
        }
    }
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Discovery::Unavailable(_) => Some("unavailable"),
            Discovery::NotJoined => Some("not_joined"),
            Discovery::NoneAdvertising => Some("none_advertising"),
            Discovery::Found(_) => None,
        }
    }
}

fn bootstrap_node(multiaddr: &str) -> Result<Value, String> {
    let (addr, peer_id) = multiaddr
        .rsplit_once("/p2p/")
        .filter(|(addr, peer_id)| !addr.is_empty() && !peer_id.is_empty() && !peer_id.contains('/'))
        .ok_or_else(|| format!("bootstrap peer is not a /p2p/ multiaddr: {multiaddr}"))?;
    Ok(json!({ "peerId": peer_id, "addrs": [addr] }))
}

pub fn node_config(bootstrap_peers: &[String]) -> Result<Value, String> {
    let mut nodes: Vec<Value> = Vec::new();
    for peer in bootstrap_peers {
        let node = bootstrap_node(peer)?;
        if !nodes.iter().any(|seen| seen["peerId"] == node["peerId"]) {
            nodes.push(node);
        }
    }
    Ok(json!({ "bootstrapNodes": nodes }))
}

pub fn bring_node_up(bootstrap_peers: &[String]) -> Result<(), String> {
    let config = node_config(bootstrap_peers)?;
    match lp::call_node("createNode", &json!([config.to_string()]), NODE_TIMEOUT_MS) {
        Ok(_) => {}
        Err(e) if e.contains("already created") => {}
        Err(e) => return Err(e),
    }
    match lp::call_node("start", &json!([]), NODE_TIMEOUT_MS) {
        Err(e) if !e.to_lowercase().contains("timeout") => Err(e),
        _ => Ok(()),
    }
}

fn node_for_discovery(bootstrap_peers: &[String]) -> Result<(), String> {
    if bootstrap_peers.is_empty() {
        return Err(NO_BOOTSTRAP_PEER.to_owned());
    }
    bring_node_up(bootstrap_peers)
}

pub fn lookup(
    service_id: &str,
    scope: &str,
    auth_type: &str,
    bootstrap_peers: &[String],
) -> (Discovery, usize) {
    if let Err(e) = node_for_discovery(bootstrap_peers) {
        return (Discovery::Unavailable(e), 0);
    }
    look(service_id, scope, auth_type)
}

fn look(service_id: &str, scope: &str, auth_type: &str) -> (Discovery, usize) {
    if let Err(e) = lp::call_node(
        "discoRegisterInterest",
        &json!([service_id]),
        DISCO_TIMEOUT_MS,
    ) {
        return (Discovery::Unavailable(e), 0);
    }
    let peers = match wait_joined() {
        Ok(0) => return (Discovery::NotJoined, 0),
        Ok(n) => n,
        Err(e) => return (Discovery::Unavailable(e), 0),
    };
    for wait in LOOKUP_WAITS_S {
        if wait > 0 {
            sleep_s(wait);
        }
        let reply = match lp::call_node("discoLookup", &json!([service_id, ""]), DISCO_TIMEOUT_MS) {
            Ok(r) => r,
            Err(e) => return (Discovery::Unavailable(e), peers),
        };
        let found = candidates_in(&reply, service_id, scope, auth_type);
        if !found.is_empty() {
            return (Discovery::Found(found), peers);
        }
    }
    (Discovery::NoneAdvertising, peers)
}

pub fn discover<A: ClientAction>(
    scope: &str,
    auth_type: &str,
    bootstrap_peers: &[String],
) -> Result<Value, String> {
    let (outcome, peers) = lookup(A::CODEC, scope, auth_type, bootstrap_peers);
    let candidates = match &outcome {
        Discovery::Unavailable(_) => return Err(outcome.message(A::PROVIDER, scope, auth_type)),
        Discovery::Found(c) => c.iter().map(Candidate::json).collect::<Vec<_>>(),
        Discovery::NotJoined | Discovery::NoneAdvertising => Vec::new(),
    };
    Ok(json!({
        "serviceId": A::CODEC,
        "candidates": candidates,
        "joined": outcome != Discovery::NotJoined,
        "peers": peers,
    }))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    NoProvider,
    Refused,
    NotSubmitted,
    Unconfirmed,
    Failed,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::NoProvider => "no_provider",
            Kind::Refused => "refused",
            Kind::NotSubmitted => "not_submitted",
            Kind::Unconfirmed => "unconfirmed",
            Kind::Failed => "failed",
        }
    }
}

#[derive(Debug)]
pub struct Failure {
    pub kind: Kind,
    pub error: String,
    pub provider: Option<(String, bool)>,
    pub code: Option<String>,
    pub discovery: Option<&'static str>,
}

impl Failure {
    pub fn json(&self, peer_key: &str) -> Value {
        let mut out = json!({ "kind": self.kind.as_str(), "error": self.error });
        if let Some((peer, discovered)) = &self.provider {
            out[peer_key] = json!(peer);
            out["discovered"] = json!(discovered);
        }
        if let Some(code) = &self.code {
            out["reason"] = json!(code);
        }
        if self.kind == Kind::Unconfirmed {
            out["unconfirmed"] = json!(true);
        }
        if let Some(why) = self.discovery {
            out["discovery"] = json!(why);
        }
        out
    }
}

struct Ended {
    kind: Kind,
    message: String,
    code: Option<String>,
    replied: bool,
    next: bool,
}

impl Ended {
    fn unreached(message: String) -> Self {
        Ended {
            kind: Kind::NoProvider,
            message,
            code: None,
            replied: false,
            next: true,
        }
    }

    fn broken(message: String) -> Self {
        Ended {
            kind: Kind::Failed,
            message,
            code: None,
            replied: false,
            next: false,
        }
    }
}

fn ask<A: ClientAction, M: AsRef<str>>(
    action: &A,
    peer_id: &str,
    addrs: &[M],
    req: &SponsorRequest,
    request_b64: &str,
) -> Result<Value, Ended> {
    let mut pr_args = json!({
        "peerId": peer_id,
        "multiaddrs": null,
        "proto": A::CODEC,
        "requestB64": request_b64,
        "timeoutMs": REQUEST_TIMEOUT_MS,
    });
    pr_args["multiaddrs"] = addrs.iter().map(|a| a.as_ref()).collect();
    let pr = match lp::call_node(
        "protocolRequest",
        &json!([pr_args.to_string()]),
        REQUEST_CALL_TIMEOUT_MS,
    ) {
        Ok(v) => v,
        Err(e)
            if e.contains("dial failed")
                || e.contains("dial returned no stream")
                || e.contains("write failed") =>
        {
            return Err(Ended::unreached(e))
        }
        Err(e) => return Err(Ended::broken(e)),
    };
    let resp_b64 = pr
        .get("responseB64")
        .and_then(Value::as_str)
        .ok_or_else(|| Ended::broken(format!("protocolRequest: no responseB64 in {pr}")))?;
    let frame = b64_decode(resp_b64).map_err(Ended::broken)?;
    let resp = SponsorResponse::decode(&frame).map_err(Ended::broken)?;
    if resp.request_id != req.request_id {
        return Err(Ended::broken(format!(
            "{} response requestId mismatch",
            A::PROVIDER
        )));
    }
    let replied = |kind: Kind, next: bool, message: Option<String>, code: Option<String>| Ended {
        kind,
        message: message.unwrap_or_else(|| format!("{} gave no reason", A::PROVIDER)),
        code,
        replied: true,
        next,
    };
    match resp.status {
        Status::Granted => {
            let unusable = |why: String| replied(Kind::Failed, false, Some(why), None);
            let result = resp
                .result
                .ok_or_else(|| unusable(format!("{} granted without a result", A::PROVIDER)))?;
            action.grant(&result, peer_id).map_err(unusable)
        }
        Status::Refused => Err(replied(Kind::Refused, true, resp.message, resp.code)),
        Status::NotSubmitted => Err(replied(Kind::NotSubmitted, true, resp.message, None)),
        Status::Unconfirmed => Err(replied(Kind::Unconfirmed, false, resp.message, None)),
    }
}

pub fn auth_payload<'a>(
    args: &'a Value,
    domain: &str,
    action: &[u8; 32],
) -> Result<(&'a str, Vec<u8>), String> {
    let auth_type = args.get("authType").and_then(Value::as_str).unwrap_or("");
    let payload_hex = args
        .get("authPayload")
        .and_then(Value::as_str)
        .unwrap_or("");
    let provider = args
        .get("authProvider")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !payload_hex.is_empty() && !provider.is_empty() {
        return Err("authPayload and authProvider are mutually exclusive".into());
    }
    if auth_type.is_empty() && (!payload_hex.is_empty() || !provider.is_empty()) {
        return Err("authPayload/authProvider need an explicit authType".into());
    }
    if provider.is_empty() {
        let payload = hex::decode(payload_hex.trim_start_matches("0x"))
            .map_err(|e| format!("authPayload hex: {e}"))?;
        return Ok((auth_type, payload));
    }
    let prod_req = ProduceRequestRef {
        auth_type,
        domain,
        action_hex: &hex::encode(action),
        args: args.get("authArgs"),
    };
    let prod_json =
        serde_json::to_string(&prod_req).map_err(|e| format!("produce request: {e}"))?;
    let reply = lp::call_module_json(
        provider,
        auth_vector::PRODUCE_METHOD,
        &json!([prod_json]),
        PRODUCE_TIMEOUT_MS,
    )?;
    let reply = auth_vector::parse_produce_reply(&reply)
        .map_err(|e| format!("auth provider {provider}: {e}"))?;
    let payload = hex::decode(reply.payload_hex.trim_start_matches("0x"))
        .map_err(|e| format!("auth provider payload hex: {e}"))?;
    Ok((auth_type, payload))
}

pub struct Route<'a> {
    pub discover: bool,
    pub configured: Option<(&'a str, &'a str)>,
    pub spread: usize,
    pub bootstrap_peers: &'a [String],
}

pub fn request<A: ClientAction>(
    action: &A,
    route: &Route<'_>,
    req: &SponsorRequest,
) -> Result<Value, Failure> {
    let request_b64 = b64(&req.encode());
    let auth_type = String::from_utf8_lossy(&req.authentication_type);
    let mut tried: Vec<String> = Vec::new();
    let mut last: Option<(String, Ended)> = None;
    let mut discovery = None;
    let node = node_for_discovery(route.bootstrap_peers);
    if let (true, Some(scope)) = (route.discover, req.scope.as_deref()) {
        let outcome = match &node {
            Ok(()) => look(A::CODEC, scope, &auth_type).0,
            Err(e) => Discovery::Unavailable(e.clone()),
        };
        match outcome {
            Discovery::Found(mut found) => {
                let at = route.spread % found.len();
                found.rotate_left(at);
                for c in found {
                    match ask(action, &c.peer_id, &c.addrs, req, &request_b64) {
                        Ok(mut out) => {
                            out["discovered"] = json!(true);
                            return Ok(out);
                        }
                        Err(ended) if ended.next => {
                            tried.push(format!("{}: {}", c.peer_id, ended.message));
                            last = ended.replied.then_some((c.peer_id, ended));
                        }
                        Err(ended) => {
                            return Err(Failure {
                                kind: ended.kind,
                                error: format!("{}: {}", c.peer_id, ended.message),
                                provider: ended.replied.then_some((c.peer_id, true)),
                                code: ended.code,
                                discovery: None,
                            });
                        }
                    }
                }
            }
            outcome => {
                tried.push(outcome.message(A::PROVIDER, scope, &auth_type));
                discovery = outcome.code();
            }
        }
    }
    if let Some((peer_id, multiaddr)) = route.configured {
        let up = if route.bootstrap_peers.is_empty() {
            bring_node_up(route.bootstrap_peers)
        } else {
            node
        };
        if let Err(e) = up {
            tried.insert(0, e);
            return Err(Failure {
                kind: Kind::NoProvider,
                error: tried.join("; before that: "),
                provider: None,
                code: None,
                discovery,
            });
        }
        return match ask(action, peer_id, &[multiaddr], req, &request_b64) {
            Ok(mut out) => {
                out["discovered"] = json!(false);
                Ok(out)
            }
            Err(ended) => Err(Failure {
                kind: ended.kind,
                error: if tried.is_empty() {
                    ended.message
                } else {
                    format!("{}; before that: {}", ended.message, tried.join("; "))
                },
                provider: ended.replied.then(|| (peer_id.to_owned(), false)),
                code: ended.code,
                discovery: discovery.filter(|_| ended.kind == Kind::NoProvider),
            }),
        };
    }
    let error = format!(
        "no {} granted and none is configured: {}",
        A::PROVIDER,
        tried.join("; ")
    );
    Err(match last {
        Some((peer, ended)) => Failure {
            kind: ended.kind,
            error,
            provider: Some((peer, true)),
            code: ended.code,
            discovery: None,
        },
        None => Failure {
            kind: Kind::NoProvider,
            error,
            provider: None,
            code: None,
            discovery,
        },
    })
}

#[cfg(test)]
mod tests {
    use paymaster_wire::service_data;

    use super::*;

    struct Toy;

    impl ClientAction for Toy {
        const CODEC: &'static str = "/test/toy/1.0.0";

        fn grant(&self, result: &[u8], peer_id: &str) -> Result<Value, String> {
            let got = std::str::from_utf8(result).map_err(|e| e.to_string())?;
            Ok(json!({ "by": peer_id, "got": got }))
        }
    }

    const SCOPE: &str = "s1";

    fn req() -> SponsorRequest {
        SponsorRequest {
            request_id: "r".into(),
            action_kind: "toy/do".into(),
            action: b"x".to_vec(),
            scope: Some(SCOPE.into()),
            ..Default::default()
        }
    }

    #[derive(Clone)]
    enum Answer {
        Dial,
        Reply(Status, Option<&'static str>, Option<&'static str>),
        Frame(Vec<u8>),
    }

    fn granted() -> Answer {
        Answer::Reply(Status::Granted, None, None)
    }

    fn scripted(peers: usize, records: Value, answer: Answer) {
        lp::fake::install(Box::new(move |_, method, _| match method {
            "createNode" | "start" => Ok(json!(true)),
            "discoRegisterInterest" => Ok(json!(true)),
            "connectedPeers" => Ok(json!((0..peers)
                .map(|i| format!("P{i}"))
                .collect::<Vec<_>>())),
            "discoLookup" => Ok(records.clone()),
            "protocolRequest" => {
                let frame = match &answer {
                    Answer::Dial => return Err("protocolRequest: dial failed".into()),
                    Answer::Frame(f) => f.clone(),
                    Answer::Reply(status, message, code) => SponsorResponse {
                        request_id: "r".into(),
                        status: *status,
                        message: message.map(str::to_owned),
                        result: (*status == Status::Granted).then(|| b"ok".to_vec()),
                        code: code.map(str::to_owned),
                    }
                    .encode(),
                };
                Ok(json!({ "responseB64": b64(&frame) }))
            }
            m => Err(format!("unscripted {m}")),
        }));
    }

    fn advertising(peers: &[&str], auth_type: &str) -> Value {
        let data = service_data(&[(SCOPE, auth_type)]).unwrap();
        peers
            .iter()
            .map(|peer| {
                json!({ "peerId": peer, "seqNo": 1, "addrs": ["/ip4/127.0.0.1/tcp/1"],
                        "services": [{ "id": Toy::CODEC, "data": b64(data.as_bytes()) }] })
            })
            .collect()
    }

    #[test]
    fn a_lookup_reply_yields_the_providers_advertising_the_pair() {
        let (d, m) = (hex::encode([0xd; 32]), hex::encode([0xa; 32]));
        let data = service_data(&[(d.as_str(), "peer-any")]).unwrap();
        let rec = |peer: &str, data: &str, addrs: Value| {
            json!({ "peerId": peer, "seqNo": 1, "addrs": addrs,
                    "services": [{ "id": Toy::CODEC, "data": b64(data.as_bytes()) }] })
        };
        let reply = json!([
            rec("A", &data, json!(["/ip4/127.0.0.1/tcp/1"])),
            rec("B", &data, json!([])),
            rec("A", &data, json!(["/ip4/127.0.0.1/tcp/2"])),
            rec("C", "zzzz", json!(["/ip4/127.0.0.1/tcp/3"])),
            json!({ "peerId": "D", "addrs": ["/ip4/127.0.0.1/tcp/4"],
                    "services": [{ "id": "/other", "data": b64(data.as_bytes()) }] }),
        ]);
        let found =
            |scope: &str, auth_type: &str| candidates_in(&reply, Toy::CODEC, scope, auth_type);
        assert_eq!(
            found(&d, "peer-any"),
            [Candidate {
                peer_id: "A".into(),
                addrs: vec!["/ip4/127.0.0.1/tcp/1".into()]
            }]
        );
        assert!(found(&m, "peer-any").is_empty());
        assert!(found(&d, "eth-allowlist").is_empty());
        assert!(candidates_in(&json!([]), Toy::CODEC, &d, "peer-any").is_empty());
        assert!(candidates_in(&json!(null), Toy::CODEC, &d, "peer-any").is_empty());
    }

    #[test]
    fn a_lookup_says_why_it_found_nobody() {
        let t = "peer-any";
        let look = || lookup(Toy::CODEC, SCOPE, t, &peers());

        lp::fake::install(Box::new(|_, m, _| match m {
            "createNode" | "start" => Ok(json!(true)),
            m => Err(format!("{m}: service discovery not mounted")),
        }));
        let (d, _) = look();
        assert_eq!(
            d.message("provider", SCOPE, t),
            "discovery unavailable: discoRegisterInterest: service discovery not mounted"
        );
        assert_eq!(d.code(), Some("unavailable"));

        scripted(0, json!([]), granted());
        assert_eq!(look(), (Discovery::NotJoined, 0));
        assert_eq!(
            Discovery::NotJoined.message("provider", SCOPE, t),
            "discovery not joined: no connected peer after 20s"
        );
        assert_eq!(now_s(), lp::fake::START_S + JOIN_WAIT_S);
        assert!(!lp::fake::methods().iter().any(|m| m == "discoLookup"));

        scripted(2, json!([]), granted());
        assert_eq!(look(), (Discovery::NoneAdvertising, 2));
        assert_eq!(
            Discovery::NoneAdvertising.message("provider", SCOPE, t),
            "no provider advertises s1/peer-any"
        );
        assert_eq!(
            lp::fake::methods()
                .iter()
                .filter(|m| *m == "discoLookup")
                .count(),
            LOOKUP_WAITS_S.len()
        );
        assert_eq!(
            now_s(),
            lp::fake::START_S + LOOKUP_WAITS_S.iter().sum::<u64>()
        );

        scripted(1, advertising(&["A"], t), granted());
        assert_eq!(
            look(),
            (
                Discovery::Found(vec![Candidate {
                    peer_id: "A".into(),
                    addrs: vec!["/ip4/127.0.0.1/tcp/1".into()]
                }]),
                1
            )
        );
        assert_eq!(
            lp::fake::calls()[3],
            (
                "connectedPeers".to_string(),
                json!([lp::PEER_DIRECTION_OUTBOUND])
            )
        );

        scripted(0, json!([]), granted());
        assert_eq!(
            discover::<Toy>(SCOPE, "", &peers()).unwrap(),
            json!({ "serviceId": Toy::CODEC, "candidates": [], "joined": false, "peers": 0 })
        );
        lp::fake::install(Box::new(|_, m, _| Err(format!("{m}: libp2p down"))));
        assert_eq!(
            discover::<Toy>(SCOPE, "", &peers()).unwrap_err(),
            "discovery unavailable: createNode: libp2p down"
        );
        lp::fake::clear();
    }

    fn peers() -> Vec<String> {
        vec![
            "/dns4/a.example/tcp/30303/p2p/PeerA".to_string(),
            "/ip4/10.0.0.2/tcp/1/p2p/PeerB".to_string(),
        ]
    }

    #[test]
    fn a_node_config_names_each_given_peer_once() {
        let mut given = peers();
        given.push("/ip4/9.9.9.9/tcp/9/p2p/PeerB".to_string());
        assert_eq!(
            node_config(&given).unwrap(),
            json!({
                "bootstrapNodes": [
                    { "peerId": "PeerA", "addrs": ["/dns4/a.example/tcp/30303"] },
                    { "peerId": "PeerB", "addrs": ["/ip4/10.0.0.2/tcp/1"] },
                ],
            })
        );
        assert_eq!(node_config(&[]).unwrap(), json!({ "bootstrapNodes": [] }));
        for bad in [
            "/ip4/10.0.0.2/tcp/1",
            "/p2p/PeerA",
            "/ip4/1.1.1.1/tcp/1/p2p/",
        ] {
            let e = node_config(&[bad.to_string()]).unwrap_err();
            assert!(e.contains("not a /p2p/ multiaddr"), "{bad}: {e}");
        }
    }

    fn with_node(create: Result<Value, String>, start: Result<Value, String>) {
        lp::fake::install(Box::new(move |_, method, _| match method {
            "createNode" => create.clone(),
            "start" => start.clone(),
            "discoRegisterInterest" => Ok(json!(true)),
            "connectedPeers" => Ok(json!(["P0"])),
            "discoLookup" => Ok(advertising(&["A"], "peer-any")),
            m => Err(format!("unscripted {m}")),
        }));
    }

    #[test]
    fn a_lookup_with_peers_brings_the_node_up_first() {
        let look = || lookup(Toy::CODEC, SCOPE, "peer-any", &peers()).0;
        let found = |d: &Discovery| matches!(d, Discovery::Found(c) if c.len() == 1);

        with_node(Ok(json!(true)), Ok(json!(true)));
        assert!(found(&look()));
        let calls = lp::fake::calls();
        assert_eq!(
            lp::fake::methods()[..3],
            ["createNode", "start", "discoRegisterInterest"]
        );
        let config: Value = serde_json::from_str(calls[0].1[0].as_str().unwrap()).unwrap();
        assert_eq!(config.as_object().unwrap().len(), 1);
        assert_eq!(
            config["bootstrapNodes"][0],
            json!({ "peerId": "PeerA", "addrs": ["/dns4/a.example/tcp/30303"] })
        );
        assert_eq!(calls[1].1, json!([]));

        with_node(
            Err("createNode: node already created".into()),
            Ok(json!(true)),
        );
        assert!(found(&look()));
        assert_eq!(lp::fake::methods()[1], "start");

        with_node(
            Ok(json!(true)),
            Err("start: Failed to start libp2p: timeout".into()),
        );
        assert!(found(&look()));

        with_node(Err("createNode: bad transport".into()), Ok(json!(true)));
        assert_eq!(
            look(),
            Discovery::Unavailable("createNode: bad transport".into())
        );
        assert_eq!(lp::fake::methods(), ["createNode"]);

        with_node(Ok(json!(true)), Err("start: no listen address".into()));
        assert_eq!(
            look(),
            Discovery::Unavailable("start: no listen address".into())
        );

        with_node(Ok(json!(true)), Ok(json!(true)));
        assert_eq!(
            lookup(Toy::CODEC, SCOPE, "peer-any", &[]).0,
            Discovery::Unavailable(NO_BOOTSTRAP_PEER.into())
        );

        let bad = vec!["/ip4/10.0.0.2/tcp/1".to_string()];
        let (d, _) = lookup(Toy::CODEC, SCOPE, "peer-any", &bad);
        assert_eq!(d.code(), Some("unavailable"));
        assert!(lp::fake::methods().is_empty());
        lp::fake::clear();
    }

    #[test]
    fn a_request_with_peers_brings_the_node_up_before_it_asks() {
        let peers = peers();
        let direct = Route {
            discover: false,
            configured: Some(("G", "/m")),
            spread: 0,
            bootstrap_peers: &peers,
        };
        lp::fake::install(Box::new(|_, method, _| match method {
            "createNode" | "start" => Ok(json!(true)),
            "protocolRequest" => Ok(json!({ "responseB64": b64(&SponsorResponse {
                request_id: "r".into(),
                status: Status::Granted,
                message: None,
                result: Some(b"ok".to_vec()),
                code: None,
            }
            .encode()) })),
            m => Err(format!("unscripted {m}")),
        }));
        assert_eq!(
            request(&Toy, &direct, &req()).unwrap(),
            json!({ "by": "G", "got": "ok", "discovered": false })
        );
        assert_eq!(
            lp::fake::methods(),
            ["createNode", "start", "protocolRequest"]
        );

        let discovering = Route {
            discover: true,
            configured: None,
            spread: 0,
            bootstrap_peers: &peers,
        };
        lp::fake::install(Box::new(|_, method, _| match method {
            "createNode" => Err("createNode: bad transport".into()),
            m => Err(format!("unscripted {m}")),
        }));
        let f = request(&Toy, &discovering, &req()).unwrap_err();
        assert_eq!(f.json("peer")["kind"], "no_provider");
        assert_eq!(f.json("peer")["discovery"], "unavailable");
        assert_eq!(lp::fake::methods(), ["createNode"]);
        lp::fake::clear();
    }

    #[test]
    fn providers_are_asked_in_turn_until_one_acts_on_the_request() {
        let peers = peers();
        let route = |configured| Route {
            discover: true,
            configured,
            spread: 1,
            bootstrap_peers: &peers,
        };
        let asked = || {
            lp::fake::calls()
                .into_iter()
                .filter(|(m, _)| m == "protocolRequest")
                .map(|(_, a)| {
                    let args: Value = serde_json::from_str(a[0].as_str().unwrap()).unwrap();
                    assert_eq!(args["proto"], Toy::CODEC);
                    assert_eq!(args["requestB64"], b64(&req().encode()));
                    args["peerId"].as_str().unwrap().to_string()
                })
                .collect::<Vec<_>>()
        };

        scripted(1, advertising(&["A", "B"], ""), granted());
        assert_eq!(
            request(&Toy, &route(None), &req()).unwrap(),
            json!({ "by": "B", "got": "ok", "discovered": true })
        );
        assert_eq!(asked(), ["B"]);

        let refuse = Answer::Reply(Status::Refused, Some("denied"), Some("auth_rejected"));
        scripted(1, advertising(&["A", "B"], ""), refuse);
        let f = request(&Toy, &route(Some(("G", "/m"))), &req()).unwrap_err();
        assert_eq!(asked(), ["B", "A", "G"]);
        assert_eq!(
            f.json("peer"),
            json!({
                "kind": "refused",
                "reason": "auth_rejected",
                "error": "denied; before that: B: denied; A: denied",
                "peer": "G",
                "discovered": false,
            })
        );

        scripted(
            1,
            advertising(&["A", "B"], ""),
            Answer::Reply(Status::NotSubmitted, Some("no funds"), None),
        );
        let f = request(&Toy, &route(None), &req()).unwrap_err();
        assert_eq!(asked(), ["B", "A"]);
        assert_eq!(
            f.json("peer"),
            json!({
                "kind": "not_submitted",
                "error": "no provider granted and none is configured: B: no funds; A: no funds",
                "peer": "A",
                "discovered": true,
            })
        );

        scripted(
            1,
            advertising(&["A", "B"], ""),
            Answer::Reply(Status::Unconfirmed, Some("not on chain"), None),
        );
        let f = request(&Toy, &route(Some(("G", "/m"))), &req()).unwrap_err();
        assert_eq!(asked(), ["B"]);
        assert_eq!(
            f.json("peer"),
            json!({
                "kind": "unconfirmed",
                "error": "B: not on chain",
                "peer": "B",
                "discovered": true,
                "unconfirmed": true,
            })
        );

        scripted(1, advertising(&["A"], ""), Answer::Dial);
        let f = request(&Toy, &route(None), &req()).unwrap_err();
        assert_eq!(
            f.json("peer"),
            json!({
                "kind": "no_provider",
                "error": "no provider granted and none is configured: A: protocolRequest: dial failed",
            })
        );
        scripted(1, json!([]), granted());
        let f = request(&Toy, &route(None), &req()).unwrap_err();
        assert_eq!(f.json("peer")["kind"], "no_provider");
        assert_eq!(f.json("peer")["discovery"], "none_advertising");
        scripted(0, json!([]), Answer::Dial);
        let f = request(&Toy, &route(Some(("G", "/m"))), &req()).unwrap_err();
        assert_eq!(f.json("peer")["kind"], "no_provider");
        assert_eq!(f.json("peer")["discovery"], "not_joined");
        scripted(1, advertising(&["A"], ""), granted());
        let direct = Route {
            discover: false,
            configured: Some(("G", "/m")),
            spread: 0,
            bootstrap_peers: &[],
        };
        assert_eq!(
            request(&Toy, &direct, &req()).unwrap(),
            json!({ "by": "G", "got": "ok", "discovered": false })
        );
        assert_eq!(asked(), ["G"]);
        lp::fake::clear();
    }

    #[test]
    fn a_reply_that_cannot_be_used_stops_without_another_provider() {
        let peers = peers();
        let route = Route {
            discover: true,
            configured: Some(("G", "/m")),
            spread: 0,
            bootstrap_peers: &peers,
        };
        let asked = || {
            lp::fake::methods()
                .iter()
                .filter(|m| *m == "protocolRequest")
                .count()
        };

        let other = SponsorResponse {
            request_id: "other".into(),
            status: Status::Granted,
            message: None,
            result: Some(b"ok".to_vec()),
            code: None,
        };
        for frame in [vec![0xff], other.encode()] {
            scripted(1, advertising(&["A", "B"], ""), Answer::Frame(frame));
            let f = request(&Toy, &route, &req()).unwrap_err();
            assert_eq!(f.kind, Kind::Failed, "{f:?}");
            assert_eq!(f.provider, None);
            assert_eq!(asked(), 1);
        }
        let empty = SponsorResponse {
            request_id: "r".into(),
            status: Status::Granted,
            message: None,
            result: None,
            code: None,
        };
        scripted(
            1,
            advertising(&["A", "B"], ""),
            Answer::Frame(empty.encode()),
        );
        let f = request(&Toy, &route, &req()).unwrap_err();
        assert_eq!(f.kind, Kind::Failed);
        assert_eq!(f.error, "A: provider granted without a result");
        assert_eq!(f.provider, Some(("A".to_string(), true)));
        assert_eq!(asked(), 1);
        lp::fake::clear();
    }

    #[test]
    fn the_auth_payload_is_raw_produced_or_empty() {
        let action = [7u8; 32];
        let auth =
            |args: Value| auth_payload(&args, "toy", &action).map(|(t, p)| (t.to_string(), p));
        assert_eq!(auth(json!({})).unwrap(), (String::new(), Vec::new()));
        assert_eq!(
            auth(json!({ "authType": "peer-any" })).unwrap(),
            ("peer-any".to_string(), Vec::new())
        );
        assert_eq!(
            auth(json!({ "authType": "t", "authPayload": "0x0aff" })).unwrap(),
            ("t".to_string(), vec![0x0a, 0xff])
        );
        for (args, needle) in [
            (
                json!({ "authType": "t", "authPayload": "aa", "authProvider": "m" }),
                "mutually exclusive",
            ),
            (json!({ "authPayload": "aa" }), "need an explicit authType"),
            (json!({ "authProvider": "m" }), "need an explicit authType"),
            (
                json!({ "authType": "t", "authPayload": "zz" }),
                "authPayload hex",
            ),
        ] {
            let e = auth(args.clone()).unwrap_err();
            assert!(e.contains(needle), "{args}: {e}");
        }

        lp::fake::install(Box::new(move |target, method, a| {
            assert_eq!((target, method), ("signer", auth_vector::PRODUCE_METHOD));
            let req: Value = serde_json::from_str(a[0].as_str().unwrap()).unwrap();
            assert_eq!(req["auth_type"], "t");
            assert_eq!(req["domain"], "toy");
            assert_eq!(req["action_hex"], hex::encode(action));
            assert_eq!(req["args"], json!({ "key": "k" }));
            Ok(json!({ "payload_hex": "beef" }))
        }));
        assert_eq!(
            auth(json!({ "authType": "t", "authProvider": "signer", "authArgs": { "key": "k" } }))
                .unwrap(),
            ("t".to_string(), vec![0xbe, 0xef])
        );
        lp::fake::clear();
    }
}
