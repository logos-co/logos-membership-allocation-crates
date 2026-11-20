use crate::ownership::bytes32;
use ark_ff::{BigInteger as _, PrimeField as _};
use blake2::{digest::consts::U32, Blake2b, Digest as _};
use logos_blockchain_poseidon2::{Digest as _, Fr, Poseidon2Bn254Hasher};
use serde_json::Value;

pub const OPCODE_CLAIM_POW_REWARD: u64 = 64;

pub struct ClaimOp {
    pub epoch_nonce: [u8; 32],
    pub block_hash: [u8; 32],
    pub public_key: [u8; 32],
}

impl ClaimOp {
    pub fn parse(op_payload: &Value) -> Result<ClaimOp, String> {
        Ok(ClaimOp {
            epoch_nonce: bytes32(&op_payload["epoch_nonce"], "op.epoch_nonce")?,
            block_hash: bytes32(&op_payload["block_hash"], "op.block_hash")?,
            public_key: bytes32(&op_payload["public_key"], "op.public_key")?,
        })
    }

    pub fn puzzle_ticket(&self) -> [u8; 32] {
        let fr = Poseidon2Bn254Hasher::digest(&[
            Fr::from_le_bytes_mod_order(&self.public_key),
            Fr::from_le_bytes_mod_order(&self.block_hash),
            Fr::from_le_bytes_mod_order(&self.epoch_nonce),
        ]);
        let mut out = [0u8; 32];
        for (o, b) in out.iter_mut().zip(fr.into_bigint().to_bytes_le()) {
            *o = b;
        }
        out
    }

    pub fn op_id(&self) -> [u8; 32] {
        let mut h = Blake2b::<U32>::new();
        h.update(b"OPERATION_ID_V1");
        h.update(self.epoch_nonce);
        h.update(self.block_hash);
        h.update(self.public_key);
        h.finalize().into()
    }
}

pub fn puzzle_ticket(op_payload: &Value) -> Result<[u8; 32], String> {
    Ok(ClaimOp::parse(op_payload)?.puzzle_ticket())
}

pub fn claim_op_id(op_payload: &Value) -> Result<[u8; 32], String> {
    Ok(ClaimOp::parse(op_payload)?.op_id())
}
