# `logos-pow-claim` — an auth vector backed by logos-blockchain PoW rewards

The vector is the `pow-claim` authoriser (`crates/pow-claim`, wrapped by
`crates/auth-vectors`) composed with the `logos` scheme: `auth_type`
`logos-pow-claim`. The contract it plugs into (the binding digest, the
payload layout, the reasons) is [`auth-vectors.md`](auth-vectors.md).

## 1. Purpose and threat model

A user runs a logos-blockchain node through basecamp/logoscore. The node's
PoW service mines reward claims. Another module on the same logoscore
instance wants an RLN membership from a service. A PoW claim costs real
work, so this vector is a candidate for *sybil resistance*, not just
identification: **one included claim = one membership**.

What it proves:

- a claim transaction is final on the chain the service's node follows;
- the reward note that claim minted is owned by, or was spent to, a wallet
  key `K`;
- the requester can obtain a zkSign signature under `K` over a message
  bound to *this* service domain, *this* action (the service's digest; for
  RLN membership it covers the identity commitment and the rate) and *this*
  claim.

What it does not prove:

- possession of `K` in isolation. The signature comes from the node's
  unauthenticated HTTP sign oracle (`POST /wallet/sign/zk`), so the
  credential is "access to the HTTP API of a node whose wallet holds `K`" —
  which is already full wallet compromise for anyone who has it. Bind the
  API to `127.0.0.1`.
- anything the trusted node does not vouch for. There is no light client
  and no inclusion proof on this chain today (§2); the verifier trusts the
  node it is pointed at.

Sybil bound: memberships ≤ PoW rewards won. A miner pays no *marginal* cost
beyond mining they would do anyway; what is bounded is the number of
memberships per unit of hashpower over time (network targets ~1 claim per
block, §2.5).

## 2. Chain primitives it builds on

All references are to `logos-blockchain/logos-blockchain` at `abd0453d9`.

### 2.1 A claim is not a proof of key possession

| Fact | Where |
|---|---|
| `ClaimPowRewardOp { epoch_nonce: ZkHash, block_hash: Hash, public_key: ZkPublicKey }` | `core/src/mantle/ops/pow.rs:82-90` |
| `Proof = NoOpProof`, opcode `0x40` — the op is **unsigned**; anyone can publish a claim for any `public_key` | `pow.rs:285-288` |
| Puzzle ticket = on-chain nullifier: `PowNullifier = Poseidon2([pk, fr_from_mod_bytes(block_hash), epoch_nonce])` | `pow.rs:93-103` |
| Execution inserts the nullifier, mints `Note::new(epoch_reward, public_key)` as `Utxo { op_id: claim.op_id(), output_index: 0, note }`, emits `PoWRewardClaimed { pow_nullifier, utxo }` | `pow.rs:343-368` |
| The node mines with a **fresh random key per ticket**; the secret keys live only in `PoWServiceState` and are pruned once the claim settles or expires. No FFI/HTTP exports them. | `services/pow/src/tickets.rs ~252-296`, `services/pow/src/service.rs:337-345, 1198-1210, 1295-1327` |
| The node's claim tx is `[Claim×≤32, Transfer, …]`: each Transfer spends the freshly minted notes (multi-signed by the mined keys over the tx hash) and pays `claim_address` | `service.rs:1486-1590` |
| The ledger verifies Transfer signatures against the **input notes' public keys** | `core/src/mantle/ops/transfer.rs:159-164` |
| Default `claim_address` is the wallet's dedicated `PoWClaim` KMS key | `nodes/node/binary/src/cli/config/init.rs:216` (`build_pow_config`) |

So the stable, challengeable identity is `claim_address` (`K`), and the
link from work to `K` is *the spend of the minted note*, which only the
mined key can authorise.

### 2.2 Signing under `K`

| Fact | Where |
|---|---|
| `POST /wallet/sign/zk { tx_hash: 32 B, pks: [ZkPublicKey] } → { sig }` signs **any** 32 bytes: `PayloadEncoding::Zk(tx_hash.to_fr())` with KMS key id `hex(fr_to_bytes(pk))` | `nodes/api-common/src/paths.rs:49`, `services/wallet/src/lib.rs:1130-1155` |
| Only KMS-registered keys; unknown id → `NotRegisteredKeyId` (HTTP 500) | `services/key-management-system/src/backend/preload.rs:85-100` |
| `TxHash::to_fr = Fr::from_le_bytes_mod_order(bytes)` | `core/src/mantle/transactions/hash.rs:122-123` |
| Signature = zkSign Groth16/BN254; compressed proof 128 B (`pi_a 32 ‖ pi_b 64 ‖ pi_c 32`); JSON `{pi_a, pi_b, pi_c}` hex | `kms/keys/src/keys/zk/signature.rs:13-26, 74-98`, `zk/groth16/src/proof/mod.rs:29` |
| Public inputs: 32 pk slots padded with `zero_pk = Poseidon2::compress([KDF, 0])`, `KDF = fr_from_bytes_unchecked(b"KDF")`, then `msg` (33 `Fr`) | `kms/keys/src/keys/zk/public.rs:88-108`, `zk/private.rs:14, 62-67`, `zk/proofs/zksign/src/public.rs:12-17` |
| Verify = `ark_groth16::Groth16::<Bn254>::verify_proof(prepared_vk, proof, inputs)`; VK is snarkjs JSON from circuits release `v0.5.7` | `zk/groth16/src/verifier.rs:30-37`, `zk/groth16/src/verification_key/mod.rs:19-60`, `zk/proofs/zksign/src/verification_key/mod.rs:15-23` |

The verifier needs only `logos-blockchain-groth16` (pure arkworks),
`logos-blockchain-poseidon2`, `blake2`, and the bundled
`zksign_vk_v0.5.7.json` (`crates/zksign-light/assets`). Depending on
`kms/keys` would drag the rapidsnark prover and a build-time artifact
download into the module.

### 2.3 Chain queries

| Route | Returns | Notes |
|---|---|---|
| `GET /cryptarchia/info` | `{ cryptarchia_info: { lib, lib_slot, tip, slot, height, state }, phase }` | `lib_slot` is **nested** (`services/chain/chain-service/src/lib.rs:234-250`) |
| `GET /cryptarchia/blocks/:id` | `{ header{id,parent_block,slot,body_root,…}, uncle_headers, transactions }` | raw storage read — **forks included** (`handlers.rs:1526-1551`) |
| `GET /cryptarchia/blocks?slot_from=&slot_to=` | immutable canonical blocks | served from the immutable-block index written only on LIB advance (`services/api/src/http/mantle.rs:626-671`, `chain-service/src/service/mod.rs:1140-1155`). **This is the canonicity primitive.** |
| `GET /cryptarchia/blocks/:id/events` | `[ { "Tx": { tx_hash, op_id, payload } }, { "Header": … } ]` | raw storage read; carries the full minted `utxo` (incl. `value = epoch_reward`, which is *not* derivable from the tx) |
| `GET /pow/status` | `{ is_mining, are_rewards_enabled, auto_claim: { is_armed, tick, targets: [ { public_key, threshold, balance } ] } }` | how the producer learns `K` (`services/pow/src/service.rs:150-170`) |

Not usable as inclusion evidence: `/cryptarchia/transaction/:id` reads the
**mempool** store (entries pruned 10 min after removal); `/mantle/status`
answers only `Unknown | Pending`. There is no PoW ledger-state endpoint, no
`pk → tx` index, no per-tx Merkle proof API (`transactions_root` is a plain
binary tree over the whole block, `core/src/utils/merkle.rs:14-30`), and no
light client.

### 2.4 Encodings the verifier parses

- `Fr`-typed fields (`ZkPublicKey`, `epoch_nonce`, `pow_nullifier`, `NoteId`)
  → 64-char lowercase hex of the **32-byte little-endian** value
  (`utils/src/lib.rs:20-27`, `zk/groth16/src/lib.rs:47-53`).
- `TxHash`, `HeaderId` → 64-char lowercase hex.
- `Hash = [u8; 32]` (`core/src/crypto.rs:4`) has **no custom serde**, so
  `ClaimPowRewardOp.block_hash`, `TxEvent.op_id` and `Utxo.op_id` arrive as
  **JSON arrays of 32 integers**.
- Block transactions are emitted through `ApiTransactionSerializer`, which
  adds `mantle_tx.hash` (`nodes/node/binary/src/api/serializers/transactions.rs:10-24`):

```json
{ "mantle_tx": { "hash": "<hex64>", "ops": [
    { "opcode": 64, "payload": { "epoch_nonce": "<hex64>", "block_hash": [u8×32], "public_key": "<hex64>" } },
    { "opcode": 0,  "payload": { "inputs": ["<NoteId hex64>", …], "outputs": [ { "value": 123, "pk": "<hex64>" } ] } } ] },
  "ops_proofs": [ { "None": null }, { "ZkSig": { "pi_a": "<hex64>", "pi_b": "<hex128>", "pi_c": "<hex64>" } } ] }
```

```json
{ "Tx": { "tx_hash": "<hex64>", "op_id": [u8×32],
          "payload": { "PoWRewardClaimed": { "pow_nullifier": "<hex64>",
                       "utxo": { "op_id": [u8×32], "output_index": 0, "note": { "value": 123, "pk": "<hex64>" } } } } } }
```

- `op_id = Blake2b-256("OPERATION_ID_V1" ‖ canonical op bytes **without** the opcode)`
  (`core/src/mantle/ops/op.rs:29-36`, `ops/mod.rs:38-45`).
- `NoteId = Poseidon2([NOTE_ID_V1, Fr::from_le_bytes_mod_order(op_id), Fr(output_index), Fr(value), pk])`,
  `NOTE_ID_V1 = fr_from_bytes(b"NOTE_ID_V1")` (`core/src/mantle/ledger.rs:491-525`).

### 2.5 Deployment parameters that matter

`slot_window = 300` slots (claim must be included within it; ledger
nullifiers prune after it). `security_param` = **30** blocks in the
standalone template, **120** on devnet/testnet
(`deployment/ceremony/genesis/*/deployment-template.yaml:23`). Target ~1
claim per block network-wide; `slot_duration` 1 s, ~20 slots per block.

## 3. Vector specification

### 3.1 `auth_type`

`logos-pow-claim`.

### 3.2 Digest and payload

```
digest  = binding_digest(logos-pow-claim, {domain, action, audience}, extra = pow_nullifier[32] LE)
msg_fr  = Fr::from_le_bytes_mod_order(digest)          -- same reduction as TxHash::to_fr
zksig   = POST /wallet/sign/zk { "tx_hash": hex(digest), "pks": [hex(K)] }
payload = K(32) ‖ zksig(128)                            -- the logos scheme part
        ‖ flags(1) ‖ claim_block_id(32) ‖ pow_nullifier(32)
        ‖ [spend_block_id(32) ‖ spend_tx_hash(32)]      -- the evidence, if flags bit0
```

`binding_digest` is `auth-vectors.md` §4.1, the payload layout its §4.2.
`K`, `pow_nullifier` are 32-byte little-endian Fr; `claim_block_id`,
`spend_block_id` are `HeaderId`s, `spend_tx_hash` a `TxHash`.

- Non-interactive and bound to the service's action, like every other
  vector (the wire has no nonce round-trip); replay is neutralised by the
  nullifier.
- `pow_nullifier` is in the digest so a signature cannot be moved between
  claims. It is globally unique: a claim's `block_hash` must be within
  `slot_window` of the including block and the ledger's nullifier set covers
  that window, so the same ticket can never be re-included after pruning.
- `audience` (default empty) names the provider; it stops a captured
  payload being replayed to another provider of the same service.
- Domain separation: real tx signatures are over
  `Blake2b-256("MANTLE_TXHASH_V1" ‖ tx)`; colliding with the binding digest
  needs a second preimage. The producer computes the digest itself and
  never signs bytes a remote party supplies.

The payload is 225 B, 289 B with the spend locator. The verifier fetches
everything else from its node; the payload only *locates* evidence.

### 3.3 Verifier algorithm (`verify_auth`)

Inputs: `VerifyRequest { auth_type, payload_hex, domain, action_hex, config }`.

1. Decode the logos part and the evidence; exact length for the flags.
   Verify the signature **first**, offline:
   `groth16_verify(vk, zksig, [K, zero_pk × 31, msg_fr])`. Milliseconds, and
   junk never costs an HTTP call.
2. `GET /cryptarchia/info` → `lib_slot`.
3. `GET /cryptarchia/blocks/{claim_block_id}` → `s = header.slot`. Reject if
   `s > lib_slot` (`not final yet`) or 404.
4. `GET /cryptarchia/blocks?slot_from=s&slot_to=s` must contain an entry
   with `header.id == claim_block_id`; that object is `B`. Reject otherwise
   (`not canonical`). A `config.node_urls` quorum is not supported; a
   non-empty list is an operator error.
5. `GET /cryptarchia/blocks/{claim_block_id}/events` → the `Tx` event whose
   `PoWRewardClaimed.pow_nullifier` equals the payload's; take
   `(tx_hash, op_id, utxo)`. Reject if absent.
6. In `B`, find `T` with `mantle_tx.hash == tx_hash`, and in `T` the
   `opcode 64` op whose recomputed ticket
   `Poseidon2([public_key, from_le_mod(block_hash), epoch_nonce])` equals the
   nullifier. Require `utxo.note.pk == op.public_key` and
   `utxo.op_id == event.op_id` (cheap consistency checks on the node's data).
7. Ownership, one of:
   - **(A) direct**: `utxo.note.pk == K`. A claim mined with `pk = K` is a
     single lottery ticket per (block, epoch) — rare but valid, and the
     strongest ownership evidence there is. Gated by
     `config.allow_direct_ownership`.
   - **(B) spent to K**: `note_id = NoteId(utxo)` (§2.4). Require an
     `opcode 0` op in `T` with `note_id ∈ inputs` and an output
     `{ pk == K, value >= min_payout }`.

   A payload with the spend locator (`bit0`) is refused before the chain
   checks: `spend locator unsupported in this PoC`, or `spend locator
   disallowed by config` when `allow_spend_locator` is false.
8. `Verdict::accept(nullifier = hex(pow_nullifier))` — 64 lowercase hex
   chars; the service namespaces it (`auth-vectors.md` §2).

**Why `note_id ∈ inputs` is the load-bearing check.** Claim ops are
unsigned, so a block proposer or mempool observer can lift an honest claim
op into their own tx `T' = [Claim(honest pk), Transfer(attacker notes → K_att)]`.
`T'` is valid (the honest tx then fails `DoubleClaimed`). A rule of the
form "some Transfer in the same tx pays `K`" would hand the honest miner's
credential to `K_att`. Requiring that the Transfer *spends the minted note*
closes this: only the mined key can sign that spend. The side effect is
that the honest miner's note then sits at the mined pk in `T'`, and that
claim cannot be redeemed: its only evidence would be the spend locator
(`bit0`), naming a later tx that sweeps the note to `K`, which the verifier
refuses (step 7).

Reject-vs-error follows the reference vectors: anything
attacker-controlled → `reject`; bad `config`, unreadable VK → `Err`
(`{"error"}` envelope). A lagging or syncing `node_url` produces transient
`not final yet` / `not canonical` rejects; callers retry.

Budget: one pairing check + 3–5 HTTP calls to a local node, well inside
the 30 s verifier window on the service's single request worker.

### 3.4 `config` schema

```json
{
  "node_url":               "http://127.0.0.1:8080",
  "node_urls":              [],                 // optional; a non-empty quorum is refused
  "audience":               "",                 // optional; must match the producer's
  "min_payout":             0,                  // optional; path B output value floor
  "allow_direct_ownership": true,               // path A
  "allow_spend_locator":    true,               // bit0; only changes the refusal reason
  "http_timeout_ms":        5000,
  "zksign_vk_path":         null,               // overrides the embedded VK (circuits v0.5.7)
  "audit_log":              null                // optional; one JSON line per decision
}
```

`node_url` is required (operator mistake → `Err`).

## 4. Producer specification

### 4.1 Where it lives

The produce half is `pow_claim::gather` (claim discovery, wrapped by
`auth_vectors::claimant::PowClaimant`) and the logos signer
(`auth_vectors::signer::LogosSigner`); a producer module composes the two.
Both talk to the user's node over its HTTP API (`http_addr`, default
`127.0.0.1:8080` — `nodes/node/binary/src/config/api/serde.rs:34-41`):
`/pow/status` for `K`, the chain reads for the scan, `/wallet/sign/zk` for
the signature. Node `0.3.0-rc.5` serves all of them.

### 4.2 `produce_auth(args_json) → json`

In: `ProduceRequest { auth_type: "logos-pow-claim", domain, action_hex, args }`.
`args` is an object or a JSON **string** holding one:

```json
{ "node_url": "http://127.0.0.1:8080",
  "audience": "",                 // optional
  "claim_block_id": "…",          // optional pin
  "pow_nullifier": "…",           // optional pin, needs claim_block_id
  "spend_block_id": "…",          // optional locator (the verifier refuses it)
  "spend_tx_hash": "…",           // optional locator, together with spend_block_id
  "exclude_nullifiers": ["…"],    // optional, for retries
  "claim_address": "…",           // optional (alias public_key); K instead of the /pow/status targets
  "allow_unfinal": false,         // optional; also walk non-final blocks back from the tip
  "scan_window_slots": 3000,      // optional; final slots scanned below lib_slot
  "scan_depth_blocks": 300,       // optional; blocks walked back from the tip
  "http_timeout_ms": 8000 }       // optional
```

Steps:

1. Candidate set `{K}`: `claim_address` if given, else `GET /pow/status`
   `auto_claim.targets[].public_key`.
2. If `pow_nullifier` is pinned, take that claim from `claim_block_id` and
   go to 4. Otherwise scan
   `GET /cryptarchia/blocks?slot_from=lib_slot−W&slot_to=lib_slot` in
   100-slot chunks, newest first, and each block's `/events`; collect
   `PoWRewardClaimed` events whose minted note satisfies path A or B for
   some `K` (path B: find the Transfer in the same tx spending `NoteId(utxo)`
   with an output to `K`). Skip `exclude_nullifiers`. With `allow_unfinal`,
   then walk up to `scan_depth_blocks` blocks back from the tip.
3. Pick the newest candidate. None → `{"error": "no redeemable PoW claim found …"}`.
4. Compute the binding digest (`auth-vectors.md` §4.1, `pow_nullifier` as
   the bound evidence) locally; `POST /wallet/sign/zk { tx_hash: hex(digest), pks: [K] }`.
5. Return `{"payload_hex"}`: the logos part followed by the evidence (§3.2).

The producer cannot know which credentials a given provider has already
spent; on a `credential already used` refusal the application retries with
that nullifier in `exclude_nullifiers`.

Out: `{"payload_hex": …}` or `{"error": …}` via `auth_vector::dispatch_produce`.

### 4.3 Requester wiring

The `request` args of a service's client:

```
"authType":     "logos-pow-claim"
"authProvider": "<producer module>"
"authArgs":     {"node_url": "http://127.0.0.1:8080"}
```

Requirements on the user's side: a node with PoW (`0.3.0-rc.5`), mining
started (`PUT /pow/mining/start` or the `blockchain_module`'s
`pow_start_mining` — off by default and not persisted across restarts,
`services/pow/src/service.rs:538-540`; the `blockchain_ui` module's Mining
view drives it through `pow_configure` / `pow_start_mining` and shows
rewards and claim history), and an auto-claim target or manual
`POST /pow/claim`. The `PoWClaim` key is one of the six predefined zk keys
created at keystore init and preloaded into the KMS
(`cli/config/keystore.rs:31-38`, `cli/config/init.rs:208-214`); a keystore
created by a node without PoW lacks it.

## 5. Operator wiring and budgets

The service's `authVerifiers` entry for `logos-pow-claim` (its shape:
[`crates/auth-vector/README.md`](../crates/auth-vector/README.md)) carries
the `config` of §3.4. The service operator runs (or points at) a node they
trust, normally their own on the service host.

| Limit | Value | This vector |
|---|---|---|
| Payload | | 225 B (289 B with locator) |
| Verifier call | 30 s, single worker | Groth16 verify (ms) + 3–5 local HTTP calls |
| Producer call | 120 s | `/pow/status` + bounded block scan + one `/wallet/sign/zk` (KMS proving, seconds) |
| Replay | nullifier store | `hex(pow_nullifier)`, once per claim per scope |
| Usable after | LIB | 30 blocks standalone, 120 blocks devnet/testnet |

## 6. Limits and privacy

- **Trusted node.** A lying `node_url` fabricates everything: the verifier
  asks one node (no quorum, §3.3 step 4) and checks no header chain (§1).
- **Sign oracle.** The HTTP API is unauthenticated and signs any 32 bytes
  with any wallet key. The credential is exactly as strong as access control
  on that port. The bundled module config listens on `0.0.0.0:8080`; users
  must bind it to `127.0.0.1`.
- **Latency.** A claim becomes usable only after LIB (30 / 120 blocks).
- **Privacy.** The service learns `K ↔ id_commitment`, and `K`'s balance
  and history are public. `K` is the dedicated `PoWClaim` key by default, so
  the exposure is "this RLN identity is the miner whose reward sink is `K`",
  not the whole wallet — unless rewards are swept into other keys. There is
  no fresh address per claim: the node's HTTP API creates no KMS keys.
- **Marginal cost.** A miner gets one membership per reward at no cost
  beyond mining they would do anyway. A membership cannot be priced at
  several claims: `Verdict.nullifier` is a single string, so a claim inside
  a bundle would stay redeemable alone or in another bundle.
- **Front-running.** A proposer can make an honest claim unredeemable
  (§3.3).
- **VK pinning.** The zkSign VK is tied to a circuit release; `zksign_vk_path`
  tracks upgrades, and the chain-crate pins must follow the network.
