use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use ark_ff::PrimeField as _;
use logos_blockchain_groth16::{
    fr_from_bytes, fr_from_bytes_unchecked, groth16_verify, CompressedGroth16Proof, Fr,
    Groth16PreparedVerificationKey, Groth16Proof, Groth16VerificationKey,
    Groth16VerificationKeyJsonDeser,
};
use logos_blockchain_poseidon2::{Digest as _, Poseidon2Bn254Hasher};

pub const DEFAULT_VK_JSON: &str = include_str!("../assets/zksign_vk_v0.5.7.json");

pub const PUBLIC_INPUTS: usize = 33;

pub struct PreparedVk(Groth16PreparedVerificationKey);

impl PreparedVk {
    pub fn from_json(vk_json: &str) -> Result<PreparedVk, String> {
        let de: Groth16VerificationKeyJsonDeser =
            serde_json::from_str(vk_json).map_err(|e| format!("zkSign vk json: {e}"))?;
        if de.ic.len() != PUBLIC_INPUTS + 1 {
            return Err(format!(
                "zkSign vk shape: IC has {} points ({} public inputs), want {} ({PUBLIC_INPUTS} public inputs)",
                de.ic.len(),
                de.ic.len().saturating_sub(1),
                PUBLIC_INPUTS + 1
            ));
        }
        let vk = Groth16VerificationKey::try_from(de)
            .map_err(|e| format!("zkSign vk convert: {e:?}"))?;
        Ok(PreparedVk(vk.into_prepared()))
    }

    pub fn from_path(path: &str) -> Result<PreparedVk, String> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| format!("config.zksign_vk_path {path}: {e}"))?;
        Self::from_json(&s).map_err(|e| format!("config.zksign_vk_path {path}: {e}"))
    }
}

static DEFAULT_VK: OnceLock<Result<PreparedVk, String>> = OnceLock::new();

pub fn default_vk() -> Result<&'static PreparedVk, String> {
    DEFAULT_VK
        .get_or_init(|| PreparedVk::from_json(DEFAULT_VK_JSON))
        .as_ref()
        .map_err(Clone::clone)
}

type VkKey = (String, Option<std::time::SystemTime>, u64);

pub fn vk_from_path_cached(path: &str) -> Result<Arc<PreparedVk>, String> {
    static CACHE: OnceLock<Mutex<HashMap<VkKey, Arc<PreparedVk>>>> = OnceLock::new();
    let meta = std::fs::metadata(path).map_err(|e| format!("config.zksign_vk_path {path}: {e}"))?;
    let key: VkKey = (path.to_string(), meta.modified().ok(), meta.len());
    let cache = CACHE.get_or_init(Default::default);
    if let Some(v) = cache.lock().unwrap_or_else(|p| p.into_inner()).get(&key) {
        return Ok(Arc::clone(v));
    }
    let v = Arc::new(PreparedVk::from_path(path)?);
    let mut c = cache.lock().unwrap_or_else(|p| p.into_inner());
    c.retain(|(p, _, _), _| p != path);
    c.insert(key, Arc::clone(&v));
    drop(c);
    Ok(v)
}

pub enum VkSource {
    Default(&'static PreparedVk),
    File(Arc<PreparedVk>),
}

impl VkSource {
    pub fn get(&self) -> &PreparedVk {
        match self {
            VkSource::Default(v) => v,
            VkSource::File(v) => v,
        }
    }
}

pub fn vk_from_config(v: Option<&serde_json::Value>) -> Result<VkSource, String> {
    match v {
        None | Some(serde_json::Value::Null) => Ok(VkSource::Default(default_vk()?)),
        Some(serde_json::Value::String(p)) if !p.trim().is_empty() => {
            Ok(VkSource::File(vk_from_path_cached(p.trim())?))
        }
        Some(v) => Err(format!(
            "config.zksign_vk_path: expected a non-empty string, got {v}"
        )),
    }
}

pub fn zero_pk() -> Fr {
    static Z: OnceLock<Fr> = OnceLock::new();
    *Z.get_or_init(|| {
        let kdf = fr_from_bytes_unchecked(b"KDF");
        Poseidon2Bn254Hasher::compress(&[kdf, Fr::from(0u64)])
    })
}

pub fn zero_pk_le() -> [u8; 32] {
    use ark_ff::BigInteger as _;
    let mut out = [0u8; 32];
    out.copy_from_slice(&zero_pk().into_bigint().to_bytes_le());
    out
}

pub fn is_canonical_fr(le: &[u8; 32]) -> bool {
    fr_from_bytes(le).is_ok()
}

pub fn verify_sig(
    vk: &PreparedVk,
    k_le: &[u8; 32],
    digest: &[u8; 32],
    zksig: &[u8; 128],
) -> Result<(), String> {
    let k = fr_from_bytes(k_le).map_err(|e| format!("zkSign signature invalid (K: {e})"))?;
    let comp = CompressedGroth16Proof::from_bytes(zksig);
    let proof = Groth16Proof::try_from(&comp)
        .map_err(|e| format!("zkSign signature invalid (proof decode: {e:?})"))?;
    let mut inputs = Vec::with_capacity(PUBLIC_INPUTS);
    inputs.push(k);
    inputs.extend(std::iter::repeat_n(zero_pk(), PUBLIC_INPUTS - 2));
    inputs.push(Fr::from_le_bytes_mod_order(digest));
    match groth16_verify(&vk.0, &proof, &inputs) {
        Ok(true) => Ok(()),
        Ok(false) => Err("zkSign signature invalid (proof does not verify)".into()),
        Err(e) => Err(format!("zkSign signature invalid (verify: {e})")),
    }
}
