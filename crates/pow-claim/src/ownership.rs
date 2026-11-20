use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    Direct,
    SpentTo,
}

impl Path {
    pub fn as_str(self) -> &'static str {
        match self {
            Path::Direct => "direct",
            Path::SpentTo => "spent_to",
        }
    }
}

pub fn tx_event(ev: &Value) -> &Value {
    ev.get("Tx").unwrap_or(ev)
}

fn lc(v: &Value) -> Option<String> {
    v.as_str().map(str::to_ascii_lowercase)
}

pub fn bytes32(v: &Value, what: &str) -> Result<[u8; 32], String> {
    match v {
        Value::Array(a) if a.len() == 32 => {
            let mut o = [0u8; 32];
            for (i, x) in a.iter().enumerate() {
                o[i] = x
                    .as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or_else(|| format!("{what}: byte {i} is not a u8: {x}"))?;
            }
            Ok(o)
        }
        Value::String(s) => crate::args::hex32_bytes(what, s),
        other => Err(format!(
            "{what}: expected 32-byte array or hex, got {other}"
        )),
    }
}

#[cfg(feature = "strict-ownership")]
mod strict {
    use ark_ff::{BigInteger as _, PrimeField as _};
    use logos_blockchain_poseidon2::{Digest as _, Fr, Poseidon2Bn254Hasher};
    use serde_json::Value;

    use super::bytes32;

    pub fn note_id_hex(utxo: &Value) -> Result<String, String> {
        let op_id = bytes32(&utxo["op_id"], "utxo.op_id")?;
        let output_index = utxo["output_index"]
            .as_u64()
            .ok_or("utxo.output_index: expected unsigned integer")?;
        let value = utxo["note"]["value"]
            .as_u64()
            .ok_or("utxo.note.value: expected unsigned integer")?;
        let pk = bytes32(&utxo["note"]["pk"], "utxo.note.pk")?;
        Ok(hex::encode(note_id(&op_id, output_index, value, &pk)))
    }

    pub fn note_id(op_id: &[u8; 32], output_index: u64, value: u64, pk: &[u8; 32]) -> [u8; 32] {
        let tag = Fr::from_le_bytes_mod_order(b"NOTE_ID_V1");
        let fr = Poseidon2Bn254Hasher::digest(&[
            tag,
            Fr::from_le_bytes_mod_order(op_id),
            Fr::from(output_index),
            Fr::from(value),
            Fr::from_le_bytes_mod_order(pk),
        ]);
        fr.into_bigint()
            .to_bytes_le()
            .try_into()
            .expect("invariant: a BN254 Fr is 32 bytes little-endian")
    }
}

#[cfg(feature = "strict-ownership")]
pub use strict::{note_id, note_id_hex};

#[cfg(not(feature = "strict-ownership"))]
pub fn note_id_hex(_utxo: &Value) -> Result<String, String> {
    Err("note_id_hex requires the strict-ownership feature".into())
}

pub fn owner(event_tx: &Value, block: &Value, ks: &[String]) -> Option<(String, Path)> {
    let ev = tx_event(event_tx);
    let claimed = &ev["payload"]["PoWRewardClaimed"];
    let utxo = &claimed["utxo"];
    let in_ks = |pk: &str| ks.iter().any(|k| k.eq_ignore_ascii_case(pk));

    if let Some(pk) = lc(&utxo["note"]["pk"]) {
        if in_ks(&pk) {
            return Some((pk, Path::Direct));
        }
    }

    let tx_hash = lc(&ev["tx_hash"])?;
    let tx = block["transactions"]
        .as_array()?
        .iter()
        .find(|t| lc(&t["mantle_tx"]["hash"]).as_deref() == Some(tx_hash.as_str()))?;

    #[cfg(feature = "strict-ownership")]
    let nid = note_id_hex(utxo).ok()?;

    for op in tx["mantle_tx"]["ops"].as_array()? {
        if op["opcode"].as_u64() != Some(0) {
            continue;
        }
        let p = &op["payload"];
        #[cfg(feature = "strict-ownership")]
        {
            let spends = p["inputs"]
                .as_array()
                .is_some_and(|ins| ins.iter().any(|i| lc(i).as_deref() == Some(nid.as_str())));
            if !spends {
                continue;
            }
        }
        if let Some(outs) = p["outputs"].as_array() {
            for o in outs {
                if let Some(pk) = lc(&o["pk"]) {
                    if in_ks(&pk) {
                        return Some((pk, Path::SpentTo));
                    }
                }
            }
        }
    }
    None
}

#[cfg(all(test, feature = "strict-ownership"))]
mod tests {
    use super::*;

    #[test]
    fn note_id_matches_upstream_kat() {
        use ark_ff::{BigInteger as _, PrimeField as _};
        use logos_blockchain_poseidon2::Fr;
        use std::str::FromStr as _;
        let mut pk = [0u8; 32];
        pk[..2].copy_from_slice(&456u16.to_le_bytes());
        let got = note_id(&[0u8; 32], 0, 100, &pk);
        let want = Fr::from_str(
            "7557997998773395727489806263315711564569794358720487479582958381680367418066",
        )
        .unwrap()
        .into_bigint()
        .to_bytes_le();
        assert_eq!(got.to_vec(), want);
        let utxo = serde_json::json!({
            "op_id": vec![0u8; 32], "output_index": 0,
            "note": {"value": 100, "pk": hex::encode(pk)}
        });
        assert_eq!(note_id_hex(&utxo).unwrap(), hex::encode(want));
    }
}
