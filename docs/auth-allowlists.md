# The allowlist authoriser, per scheme: eth, logos, lez, keycard, peer

The service operator keeps a list of identities; a requester proves, with a
signature bound to THIS request's action (the service's `action_hex` digest,
under its `domain`), that they hold one.
The identity is the nullifier, so each listed entry is spent once per scope.
The pipeline, the binding digest, the payload layout and the reasons are in
[`auth-vectors.md`](auth-vectors.md); this page is what an operator and a
requester do per scheme.

A verifier (a service's own registry, or a verifier module) composes
`auth_vectors::authoriser::Allowlist` with the
schemes it ships; each `auth_type` keeps its own entry in the service's
`authVerifiers`. A producer module composes the signers in
`auth_vectors::signer` with `AllowlistClaimant` and answers `produce_auth`
through `auth_vector::dispatch_produce`:
`{"auth_type","domain","action_hex","args"?}` -> `{"payload_hex"}` or
`{"error":"…"}`. `Signer::identity(args)` gives the identity the operator
allowlists.

Common rules:

- The verifier config is `{"allowlist": [...], "audience"?: ""}`. A missing or
  empty allowlist is an operator error (`allowlist is empty`), never a silent
  accept; one malformed entry rejects the whole list, named with its text.
- The allowlist is checked BEFORE the signature for every scheme whose part
  carries the key (logos, lez, keycard): an unlisted identity is refused by
  name without signature work. eth's identity is only known after recovery.
- `audience` comes from the producer's `args` (`""` by default) and must
  equal the verifier's `config.audience`; every scheme but peer binds it, eth
  included (`auth-vectors.md` §4.3). What else a service binds is in its
  action (`auth-vectors.md` §1).

## Summary

| | `eth-allowlist` | `logos-allowlist` | `lez-allowlist` | `keycard-allowlist` | `peer-allowlist` |
|---|---|---|---|---|---|
| Who holds the key | the producer module (its `KeySource`), or any wallet | the requester's own logos-blockchain node (its PoWClaim key); nothing is stored in the module | the producer module (its `KeySource`) | the card | the requester's `libp2p_module` (its node key; nothing is signed) |
| Producer `args` | `private_key`?, `audience` | `node_url`, `public_key`?, `http_timeout_ms`?, `audience` | `private_key`?, `audience` | `audience` | none (the payload is empty; `identity` needs `peer_id`) |
| Allowlist entry | `0x` + 40 hex address (also accepted without `0x`, in any case) | 64 hex public key K (little-endian, as the node prints it); `0x` and uppercase accepted | 64 hex account id, or its base58 form | 66 hex compressed identity key | the PeerId as libp2p prints it (base58) or its multihash hex |
| Nullifier | the address | K | the account id, 64 hex | the identity key, 66 hex | the multihash, lowercase hex |

## eth

- `EthSigner::identity` -> the lowercase `0x` address of the module's key;
  `args.private_key` (`"0x<32-byte hex>"`) signs with that key instead.
  Any wallet's `personal_sign` over the text
  `Logos <domain> authorisation: 0x<binding digest hex>` works too
  (`auth-vectors.md` §4.3): its 65-byte signature is the payload, sent as
  `authPayload`.
- Verifier config: `{"allowlist":["0x…"]}`.
- Refusals: `signature verification failed`, `address not allowlisted`,
  `allowlist is empty`.

## logos

- The key is a logos-blockchain node's PoWClaim key. The node zkSigns the
  binding digest on request (`POST /wallet/sign/zk`, about 15 s); the private
  key never leaves the node.
- `LogosSigner::identity` with `args` `{"node_url":…}` -> K: `args.public_key`,
  else the node's single `/pow/status` auto-claim target (zero or several
  targets need `public_key` in the args).
  `args`: `{"node_url":"http://127.0.0.1:8080","public_key"?,"http_timeout_ms"?,"audience"?}`.
- Verifier config: `{"allowlist":["<64 hex K>", …],"audience":""}`;
  `zksign_vk_path` optionally replaces the bundled verification key. An entry
  that is not a canonical little-endian BN254 scalar rejects the whole config
  (`big-endian paste?`).
- K is the hex `/pow/status` prints (a little-endian field element)
  everywhere; it is never reversed. The zero key is refused.
- Refusals: `public key not allowlisted`, `allowlist is empty`,
  `zkSign signature invalid (…)`.

## lez

- The key is a plain secp256k1 key held by the producer module. The account
  id is `sha256(LEE_PREFIX ‖ xonly)` over the x-only public key, the same
  derivation as a LEZ account; the base58 form is what a LEZ wallet shows.
  Importing the same private key into a LEZ wallet yields the same account.
- `LezSigner::identity` -> the account id (hex); `args`
  `{"private_key"?,"audience"?}`, `private_key` overriding the module's key.
- Verifier config: `{"allowlist":["<64 hex or base58>", …],"audience":""}`,
  entries normalised to hex.
- Refusals: `account not allowlisted`, `allowlist is empty`,
  `signature verification failed`.

## keycard

- The card's identity key (`ident_pub`, survives factory reset) is the
  identity; `KeycardSigner` (feature `keycard-pcsc`) produces the part over
  PC/SC. The same card can also be judged by its CA instead
  (`keycard-attestation`, `auth-vectors.md` §3).
- Verifier config: `{"allowlist":["<66 hex compressed key>", …]}`.
- Refusals: `card not allowlisted`, `attestation parse failed: …`,
  `attestation verification failed: …`.

## peer

- No key on the client beyond its libp2p node's: the service reads the
  requester's peer id off the accepted stream (`libp2p_module` ≥ 1.1.0) and
  that is the identity. The payload is empty: `produce_auth` answers
  `{"payload_hex": ""}`.
- `PeerSigner::identity` with `args` `{"peer_id":"<from libp2p_module.peerInfo>"}`
  -> the multihash hex an operator allowlists; `peer-any` needs no list.
- Verifier config: `{"allowlist":["12D3Koo…" | "<hex>", …]}`; `peer-any`
  takes `{}`.
- Refusals: `peer not allowlisted`, `allowlist is empty`; a service whose
  bridge reports no peer id answers `{"error":"transport peer id unavailable…"}`.
