use std::collections::HashMap;
use std::sync::Mutex;

use paymaster_lp as lp;
use serde_json::{json, Value};

use crate::lock;

pub(crate) const ADVERTISE_TIMEOUT_MS: i32 = 30_000;
const PEER_CHECK_S: u64 = 10;
const AD_REFRESH_S: u64 = 600;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AdSpec {
    pub(crate) data: String,
    pub(crate) addrs: Option<Vec<String>>,
}

#[derive(Debug)]
struct Placed {
    spec: AdSpec,
    at: u64,
    peers: usize,
}

#[derive(Default)]
pub(crate) struct AdBoard {
    pub(crate) wanted: Mutex<Option<AdSpec>>,
    pub(crate) placed: Mutex<Option<AdSpec>>,
}

#[derive(Default)]
pub(crate) struct Advertiser {
    placed: Option<Placed>,
    peers_checked_at: u64,
    last_seq_no: u64,
}

pub fn served_pairs<'a>(
    scopes: &'a [String],
    auth_verifiers: &'a HashMap<String, (Option<String>, Option<Value>)>,
) -> Vec<(&'a str, &'a str)> {
    let mut types: Vec<&str> = auth_verifiers.keys().map(String::as_str).collect();
    types.sort_unstable();
    if types.is_empty() {
        types.push("");
    }
    scopes
        .iter()
        .flat_map(|s| types.iter().map(move |t| (s.as_str(), *t)))
        .collect()
}

fn create_xpr(
    service_id: &str,
    addrs: &[String],
    data: &str,
    seq_no: u64,
) -> Result<String, String> {
    let mut services = serde_json::Map::new();
    services.insert(service_id.to_string(), lp::bstr(data.as_bytes()));
    let v = lp::call_libp2p(
        "createXpr",
        &json!([addrs, services, seq_no]),
        ADVERTISE_TIMEOUT_MS,
    )
    .map_err(|e| format!("createXpr: {e}"))?;
    v.as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("createXpr: no record in {v}"))
}

impl Advertiser {
    pub(crate) fn reconcile(
        &mut self,
        board: &AdBoard,
        service_id: &str,
        renew: bool,
        peers: usize,
    ) -> Result<(), String> {
        let wanted = {
            let wanted = lock(&board.wanted);
            if !renew && self.placed.as_ref().map(|p| &p.spec) == wanted.as_ref() {
                return Ok(());
            }
            wanted.clone()
        };
        if self.placed.is_some() {
            lp::call_libp2p(
                "discoStopAdvertising",
                &json!([service_id]),
                ADVERTISE_TIMEOUT_MS,
            )
            .map_err(|e| format!("discoStopAdvertising: {e}"))?;
            self.placed = None;
            *lock(&board.placed) = None;
        }
        if let Some(spec) = wanted {
            let at = lp::now_s();
            let seq_no = at.max(self.last_seq_no + 1);
            let record = match &spec.addrs {
                Some(addrs) => create_xpr(service_id, addrs, &spec.data, seq_no)?,
                None => String::new(),
            };
            lp::call_libp2p(
                "discoStartAdvertising",
                &json!([service_id, spec.data.as_str(), record]),
                ADVERTISE_TIMEOUT_MS,
            )
            .map_err(|e| format!("discoStartAdvertising: {e}"))?;
            if spec.addrs.is_some() {
                self.last_seq_no = seq_no;
            }
            self.peers_checked_at = at;
            *lock(&board.placed) = Some(spec.clone());
            self.placed = Some(Placed { spec, at, peers });
        }
        Ok(())
    }

    pub(crate) fn tick(&mut self, board: &AdBoard, service_id: &str) -> Result<(), String> {
        let now = lp::now_s();
        let mut peers = self.placed.as_ref().map(|p| p.peers).unwrap_or(0);
        let mut renew = false;
        if let Some(p) = &mut self.placed {
            if now >= self.peers_checked_at + PEER_CHECK_S {
                self.peers_checked_at = now;
                if let Ok(n) = lp::outbound_peers() {
                    renew |= p.peers == 0 && n > 0;
                    peers = n;
                    p.peers = n;
                }
            }
            renew |= p.spec.addrs.is_some() && now >= p.at + AD_REFRESH_S;
        }
        self.reconcile(board, service_id, renew, peers)
    }

    pub(crate) fn first(
        &mut self,
        board: &AdBoard,
        service_id: &str,
        reply: &mut Value,
        advertise_wanted: Option<bool>,
    ) -> Result<(), String> {
        let wanted = lock(&board.wanted).is_some();
        let peers = if wanted {
            lp::outbound_peers().unwrap_or(0)
        } else {
            0
        };
        if wanted {
            reply["advertisedToPeers"] = json!(peers);
        }
        match self.reconcile(board, service_id, false, peers) {
            Ok(()) => reply["advertised"] = json!(wanted),
            Err(e) if advertise_wanted == Some(true) => return Err(format!("advertise: {e}")),
            Err(e) => reply["advertiseError"] = json!(e),
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    const SID: &str = "/test/service/1.0.0";

    pub(crate) fn scripted_libp2p(peers: impl Fn() -> usize + Send + 'static) {
        lp::fake::install(Box::new(move |_, method, _| match method {
            "connectedPeers" => Ok(json!((0..peers())
                .map(|i| format!("P{i}"))
                .collect::<Vec<_>>())),
            "createXpr" => Ok(json!({ "success": true, "value": "XPRB64", "error": "" })),
            "discoStartAdvertising" | "discoStopAdvertising" => Ok(json!(true)),
            "mountProtocol" => Err("refused in test".into()),
            m => Err(format!("unscripted {m}")),
        }));
    }

    pub(crate) fn ad_calls() -> Vec<(String, Value)> {
        lp::fake::calls()
            .into_iter()
            .filter(|(m, _)| m != "connectedPeers")
            .collect()
    }

    pub(crate) fn spec(data: &str) -> AdSpec {
        AdSpec {
            data: data.into(),
            addrs: None,
        }
    }

    pub(crate) fn placed(spec: AdSpec, peers: usize) -> Advertiser {
        Advertiser {
            placed: Some(Placed {
                spec,
                at: lp::fake::START_S,
                peers,
            }),
            peers_checked_at: lp::fake::START_S,
            last_seq_no: 0,
        }
    }

    #[test]
    fn the_served_pairs_are_every_scope_with_every_verifier_type() {
        let (d, m) = ("dd".to_string(), "aa".to_string());
        let mut verifiers = HashMap::new();
        verifiers.insert("peer-any".to_string(), (None, None));
        verifiers.insert(
            "eth-allowlist".to_string(),
            (Some("auth_module".to_string()), None),
        );
        let scopes = [d.clone(), m.clone()];
        assert_eq!(
            served_pairs(&scopes, &verifiers),
            [
                (d.as_str(), "eth-allowlist"),
                (d.as_str(), "peer-any"),
                (m.as_str(), "eth-allowlist"),
                (m.as_str(), "peer-any"),
            ]
        );
        assert_eq!(
            served_pairs(std::slice::from_ref(&d), &HashMap::new()),
            [(d.as_str(), "")]
        );
    }

    #[test]
    fn the_first_advertisement_is_placed_at_once_and_re_placed_when_peers_appear() {
        let start = lp::fake::START_S;

        let board = AdBoard::default();
        scripted_libp2p(|| 2);
        *lock(&board.wanted) = Some(spec("abc"));
        let mut reply = json!({});
        Advertiser::default()
            .first(&board, SID, &mut reply, None)
            .unwrap();
        assert_eq!(reply, json!({ "advertised": true, "advertisedToPeers": 2 }));
        assert_eq!(
            lp::fake::methods(),
            ["connectedPeers", "discoStartAdvertising"]
        );
        assert_eq!(lp::now_s(), start);

        let board = AdBoard::default();
        lp::fake::install(Box::new(|_, m, _| match m {
            "connectedPeers" => Err("connectedPeers: libp2p down".into()),
            _ => Ok(json!(true)),
        }));
        *lock(&board.wanted) = Some(spec("abc"));
        let mut reply = json!({});
        Advertiser::default()
            .first(&board, SID, &mut reply, None)
            .unwrap();
        assert_eq!(reply, json!({ "advertised": true, "advertisedToPeers": 0 }));
        assert_eq!(lp::now_s(), start);

        let board = AdBoard::default();
        let up = Arc::new(AtomicBool::new(false));
        let u = Arc::clone(&up);
        scripted_libp2p(move || usize::from(u.load(Ordering::SeqCst)));
        *lock(&board.wanted) = Some(spec("abc"));
        let mut reply = json!({});
        let mut adv = Advertiser::default();
        adv.first(&board, SID, &mut reply, None).unwrap();
        assert_eq!(reply, json!({ "advertised": true, "advertisedToPeers": 0 }));
        assert_eq!(lp::now_s(), start);
        assert_eq!(ad_calls().len(), 1);
        up.store(true, Ordering::SeqCst);
        lp::fake::advance(PEER_CHECK_S);
        adv.tick(&board, SID).unwrap();
        let methods: Vec<String> = ad_calls().into_iter().map(|(m, _)| m).collect();
        assert_eq!(
            methods,
            [
                "discoStartAdvertising",
                "discoStopAdvertising",
                "discoStartAdvertising"
            ]
        );
        assert_eq!(adv.placed.as_ref().map(|p| p.peers), Some(1));
        lp::fake::clear();
    }

    #[test]
    fn the_worker_re_places_the_advertisement_when_peers_appear_or_it_ages() {
        let start = lp::fake::START_S;
        let peers = Arc::new(AtomicUsize::new(0));
        let board = AdBoard::default();
        let place = |addrs: Option<Vec<String>>, peers: usize| {
            let spec = AdSpec {
                data: "abc".into(),
                addrs,
            };
            *lock(&board.placed) = None;
            *lock(&board.wanted) = Some(spec.clone());
            placed(spec, peers)
        };
        let ad_methods = || ad_calls().into_iter().map(|(m, _)| m).collect::<Vec<_>>();

        let mut adv = place(None, 0);
        let p = Arc::clone(&peers);
        scripted_libp2p(move || p.load(Ordering::SeqCst));
        lp::fake::advance(5);
        adv.tick(&board, SID).unwrap();
        assert!(lp::fake::calls().is_empty());
        lp::fake::advance(5);
        adv.tick(&board, SID).unwrap();
        assert_eq!(lp::fake::methods(), ["connectedPeers"]);
        peers.store(1, Ordering::SeqCst);
        adv.tick(&board, SID).unwrap();
        assert_eq!(
            lp::fake::methods(),
            ["connectedPeers"],
            "within PEER_CHECK_S of the last check"
        );
        lp::fake::advance(PEER_CHECK_S);
        adv.tick(&board, SID).unwrap();
        assert_eq!(
            ad_methods(),
            ["discoStopAdvertising", "discoStartAdvertising"]
        );
        lp::fake::advance(PEER_CHECK_S);
        adv.tick(&board, SID).unwrap();
        assert_eq!(
            ad_methods().len(),
            2,
            "peers stayed up: nothing to re-place"
        );

        let mut adv = place(None, 1);
        scripted_libp2p(|| 1);
        lp::fake::advance(AD_REFRESH_S * 2);
        adv.tick(&board, SID).unwrap();
        assert!(ad_methods().is_empty());

        let addrs = vec!["/ip4/203.0.113.7/tcp/4001".to_string()];
        let mut adv = place(Some(addrs), 1);
        scripted_libp2p(|| 1);
        lp::fake::advance(AD_REFRESH_S - 1);
        adv.tick(&board, SID).unwrap();
        assert!(ad_methods().is_empty());
        lp::fake::advance(1);
        adv.tick(&board, SID).unwrap();
        let calls = ad_calls();
        assert_eq!(
            calls.iter().map(|(m, _)| m.as_str()).collect::<Vec<_>>(),
            ["discoStopAdvertising", "createXpr", "discoStartAdvertising"]
        );
        assert_eq!(calls[1].1[2], json!(start + AD_REFRESH_S));
        assert_eq!(
            adv.placed.as_ref().map(|p| p.at),
            Some(start + AD_REFRESH_S)
        );

        *lock(&board.wanted) = Some(spec("xyz"));
        adv.tick(&board, SID).unwrap();
        assert_eq!(
            ad_calls().last().unwrap(),
            &("discoStartAdvertising".to_string(), json!([SID, "xyz", ""]))
        );
        lp::fake::clear();
    }
}
