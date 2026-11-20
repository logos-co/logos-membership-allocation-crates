use serde_json::Value;

pub trait NodeApi {
    fn pow_status(&self) -> Result<Value, String>;
    fn info(&self) -> Result<Value, String>;
    fn block(&self, id_hex: &str) -> Result<Option<Value>, String>;
    fn immutable_blocks(&self, slot_from: u64, slot_to: u64) -> Result<Vec<Value>, String>;
    fn events(&self, id_hex: &str) -> Result<Vec<Value>, String>;
    fn sign_zk(&self, digest: &[u8; 32], pk_hex: &str) -> Result<[u8; 128], String>;
}

pub mod testing {
    use std::{cell::RefCell, collections::HashMap, fs, path::Path};

    use serde_json::Value;

    use super::NodeApi;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SignRequest {
        pub tx_hash: String,
        pub pk: String,
    }

    #[derive(Debug, Default)]
    pub struct FakeNode {
        pub pow_status: Value,
        pub info: Value,
        pub blocks: HashMap<String, Value>,
        pub events: HashMap<String, Vec<Value>>,
        pub immutable: Vec<Value>,
        pub sign_reply: Value,
        pub last_sign: RefCell<Option<SignRequest>>,
        pub ranges: RefCell<Vec<(u64, u64)>>,
    }

    fn read_json(p: &Path) -> Result<Value, String> {
        let s = fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        serde_json::from_str(&s).map_err(|e| format!("{}: {e}", p.display()))
    }

    impl FakeNode {
        pub fn from_dir(dir: impl AsRef<Path>) -> Result<FakeNode, String> {
            let dir = dir.as_ref();
            let opt = |name: &str| -> Result<Value, String> {
                let p = dir.join(name);
                if p.exists() {
                    read_json(&p)
                } else {
                    Ok(Value::Null)
                }
            };
            let mut n = FakeNode {
                pow_status: opt("pow_status.json")?,
                info: opt("info.json")?,
                sign_reply: opt("sign_zk.json")?,
                ..FakeNode::default()
            };
            if let Value::Array(a) = opt("immutable.json")? {
                n.immutable = a;
            }
            let rd = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            for ent in rd {
                let ent = ent.map_err(|e| e.to_string())?;
                let name = ent.file_name().to_string_lossy().to_string();
                let Some(stem) = name.strip_suffix(".json") else {
                    continue;
                };
                if let Some(id) = stem.strip_prefix("block_") {
                    n.blocks
                        .insert(id.to_ascii_lowercase(), read_json(&ent.path())?);
                } else if let Some(id) = stem.strip_prefix("events_") {
                    let Value::Array(arr) = read_json(&ent.path())? else {
                        return Err(format!("{name}: expected array"));
                    };
                    n.events.insert(id.to_ascii_lowercase(), arr);
                }
            }
            Ok(n)
        }

        pub fn add_block(&mut self, block: Value, events: Vec<Value>, immutable: bool) {
            let id = block["header"]["id"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if immutable {
                self.immutable.push(block.clone());
            }
            self.blocks.insert(id.clone(), block);
            self.events.insert(id, events);
        }

        pub fn last_sign(&self) -> Option<SignRequest> {
            self.last_sign.borrow().clone()
        }
    }

    impl NodeApi for FakeNode {
        fn pow_status(&self) -> Result<Value, String> {
            Ok(self.pow_status.clone())
        }
        fn info(&self) -> Result<Value, String> {
            Ok(self.info.clone())
        }
        fn block(&self, id_hex: &str) -> Result<Option<Value>, String> {
            Ok(self.blocks.get(&id_hex.to_ascii_lowercase()).cloned())
        }
        fn immutable_blocks(&self, slot_from: u64, slot_to: u64) -> Result<Vec<Value>, String> {
            self.ranges.borrow_mut().push((slot_from, slot_to));
            Ok(self
                .immutable
                .iter()
                .filter(|b| {
                    b["header"]["slot"]
                        .as_u64()
                        .is_some_and(|s| s >= slot_from && s <= slot_to)
                })
                .cloned()
                .collect())
        }
        fn events(&self, id_hex: &str) -> Result<Vec<Value>, String> {
            Ok(self
                .events
                .get(&id_hex.to_ascii_lowercase())
                .cloned()
                .unwrap_or_default())
        }
        fn sign_zk(&self, digest: &[u8; 32], pk_hex: &str) -> Result<[u8; 128], String> {
            *self.last_sign.borrow_mut() = Some(SignRequest {
                tx_hash: hex::encode(digest),
                pk: pk_hex.to_string(),
            });
            if self.sign_reply.is_null() {
                return Err("fake node: no sign_zk.json".into());
            }
            zksign_light::parse_sig_reply(&self.sign_reply)
        }
    }
}
