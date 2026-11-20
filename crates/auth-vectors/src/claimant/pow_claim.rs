use auth_vector::{args_object_cow, Binding, Claimant};
use pow_claim::{gather, Evidence, HttpNode, NodeApi, ProduceArgs};
use serde_json::Value;

use crate::scheme::logos::NAME as LOGOS;

pub struct PowClaimant {
    pub node: Option<Box<dyn NodeApi + Send + Sync>>,
}

impl PowClaimant {
    pub fn http() -> Self {
        PowClaimant { node: None }
    }
}

pub fn claim_args(raw: Option<&Value>) -> Result<ProduceArgs, String> {
    let mut a = ProduceArgs::parse(raw)?;
    if a.claim_address.is_none() {
        if let Some(o) = args_object_cow(raw)? {
            if let Some(Value::String(k)) = o.get("public_key") {
                a.claim_address = Some(auth_vector::norm_hex32("public_key", k)?);
            }
        }
    }
    Ok(a)
}

impl Claimant for PowClaimant {
    fn authoriser(&self) -> &'static str {
        "pow-claim"
    }
    fn accepts(&self, scheme: &str) -> bool {
        scheme == LOGOS
    }
    fn gather(&self, _b: &Binding, args: Option<&Value>) -> Result<Vec<u8>, String> {
        let a = claim_args(args)?;
        let claim = match &self.node {
            Some(n) => gather(n.as_ref(), &a)?,
            None => gather(&HttpNode::new(&a.node_url, a.http_timeout_ms), &a)?,
        };
        Ok(claim.evidence.encode())
    }
    fn extra(&self, evidence: &[u8]) -> Vec<u8> {
        Evidence::decode(evidence)
            .map(|(e, _)| e.pow_nullifier.to_vec())
            .unwrap_or_default()
    }
}
