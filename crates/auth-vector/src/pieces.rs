use std::any::Any;

use serde_json::Value;

use crate::binding::Binding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<T> {
    Ok(T),
    Reject(String),
}

pub type Check<T> = Result<Outcome<T>, String>;

pub type Cfg = Box<dyn Any + Send + Sync>;
pub type Evidence = Box<dyn Any + Send + Sync>;

pub trait Identity: Any + Send + Sync {
    fn canonical(&self) -> String;
    fn as_any(&self) -> &dyn Any;
}

pub fn downcast_identity<T: 'static>(id: &dyn Identity) -> Option<&T> {
    id.as_any().downcast_ref::<T>()
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Transport<'a> {
    pub peer_id: Option<&'a str>,
}

pub struct Decoded<'a> {
    pub claimed: Option<Box<dyn Identity>>,
    pub part: &'a [u8],
    pub rest: &'a [u8],
}

pub trait Scheme: Send + Sync {
    fn name(&self) -> &'static str;
    fn identity_noun(&self) -> &'static str {
        "identity"
    }
    fn parse_identity(&self, s: &str) -> Result<String, String>;
    fn config(&self, raw: Option<&Value>) -> Result<Cfg, String> {
        let _ = raw;
        Ok(Box::new(()))
    }
    fn decode<'a>(&self, body: &'a [u8]) -> Outcome<Decoded<'a>>;
    fn verify(
        &self,
        cfg: &dyn Any,
        b: &Binding,
        digest: &[u8; 32],
        d: &Decoded<'_>,
        t: &Transport<'_>,
    ) -> Check<Box<dyn Identity>>;
}

pub trait Signer: Send + Sync {
    fn scheme(&self) -> &'static str;
    fn sign(&self, b: &Binding, digest: &[u8; 32], args: Option<&Value>)
        -> Result<Vec<u8>, String>;
    fn identity(&self, args: Option<&Value>) -> Result<Box<dyn Identity>, String>;
}

pub trait Authoriser: Send + Sync {
    fn name(&self) -> &'static str;
    fn accepts(&self, scheme: &str) -> bool;
    fn config(&self, scheme: &dyn Scheme, raw: Option<&Value>) -> Result<Cfg, String>;
    fn audience<'a>(&self, cfg: &'a dyn Any) -> &'a str;
    fn decode_evidence<'a>(&self, rest: &'a [u8]) -> Outcome<(Evidence, &'a [u8])>;
    fn extra(&self, ev: &dyn Any) -> Vec<u8>;
    fn before_sig(&self) -> bool {
        false
    }
    fn authorise(&self, cfg: &dyn Any, id: &dyn Identity, ev: &dyn Any) -> Check<()>;
    fn nullifier(&self, id: &dyn Identity, ev: &dyn Any) -> String {
        let _ = ev;
        id.canonical()
    }
}

pub trait Claimant: Send + Sync {
    fn authoriser(&self) -> &'static str;
    fn accepts(&self, scheme: &str) -> bool;
    fn gather(&self, b: &Binding, args: Option<&Value>) -> Result<Vec<u8>, String>;
    fn extra(&self, evidence: &[u8]) -> Vec<u8>;
}
