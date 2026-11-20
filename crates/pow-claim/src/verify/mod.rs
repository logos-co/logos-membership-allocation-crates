pub mod audit;
pub mod chain;
pub mod config;
pub mod ticket;

use std::time::Instant;

use crate::{claim::Claim, node::NodeApi};

pub use chain::{check_claim, spent_to_k, ClaimCheck};
pub use config::Config;
pub use ticket::puzzle_ticket;

pub fn check(nodes: &[&dyn NodeApi], claim: &Claim, cfg: &Config) -> Result<ClaimCheck, String> {
    let t0 = Instant::now();
    let mut rec = audit::Record {
        node: cfg.node_url.clone(),
        nullifier: Some(hex::encode(claim.evidence.pow_nullifier)),
        ..Default::default()
    };
    let r = check_claim(nodes, claim, cfg);
    if let Ok(c) = &r {
        rec.lib_slot = c.lib_slot;
        if let Ok(path) = &c.outcome {
            rec.path = Some(path.as_str());
        }
    }
    let verdict = match &r {
        Ok(c) => Ok(c.outcome.clone().map(|_| ())),
        Err(e) => Err(e.clone()),
    };
    audit::record(
        cfg.audit_log.as_deref(),
        &rec,
        &verdict,
        t0.elapsed().as_millis(),
    );
    r
}
