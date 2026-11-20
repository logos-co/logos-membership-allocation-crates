use std::fmt::Display;

use crate::authtype::AuthType;
use crate::binding::MAX_DOMAIN_LEN;

pub const SIG_FAILED: &str = "signature verification failed";
pub const ALLOWLIST_EMPTY: &str = "config.allowlist is empty — nothing can verify";
pub const ENTRIES_NOT_STRINGS: &str = "config.allowlist entries must be strings";
pub const TRANSPORT_PEER_UNKNOWN: &str =
    "transport peer id unavailable: the host's libp2p bridge reports none";

pub fn sig_failed(detail: impl Display) -> String {
    format!("{SIG_FAILED}: {detail}")
}
pub fn payload_hex(e: impl Display) -> String {
    format!("payload hex: {e}")
}
pub fn action_hex(e: impl Display) -> String {
    format!("action hex: {e}")
}
pub fn action_len(got: usize) -> String {
    format!("action must be 32 bytes, got {got}")
}
pub fn bad_domain(domain: &str) -> String {
    format!("domain {domain:?}: expected 1 to {MAX_DOMAIN_LEN} bytes of [a-z0-9-]")
}
pub fn not_allowlisted(what: &str, id: &str) -> String {
    format!("{what} not allowlisted: {id}")
}
pub fn allowlist_required(what: &str) -> String {
    format!("config.allowlist (array of {what}) is required")
}
pub fn trailing_bytes(n: usize) -> String {
    format!("payload has {n} trailing bytes")
}
pub fn identity_mismatch(claimed: &str, proven: &str) -> String {
    format!("payload names {claimed} but the signature proves {proven}")
}
pub fn unknown_composition(t: &AuthType, why: impl Display) -> String {
    format!("unknown auth_type '{t}': {why}")
}
