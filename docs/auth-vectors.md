# Auth vectors

Normative for every auth vector. An auth vector lets a service submit an
on-chain transaction on behalf of a requester only after the requester has
proved, for that service and that action, who they are and that they are
allowed. The Rust types in `crates/auth-vector` are the reference; a module
in another language conforms by speaking the same JSON and bytes.

## 1. What gets authorised

Three values, all chosen outside the vector, go into what the requester
signs:

- **`domain`** — the service's name for what it authorises, for example
  `rln-membership` or `account-registry`. 1 to 64 bytes of `[a-z0-9-]`, taken
  as given (no trimming, no case folding). Each service uses its own, so a
  proof made for one service never verifies for another.
- **`action`** — 32 bytes the service computes over whatever it is asked to
  do. The vectors treat it as opaque. The service defines how it is computed
  and computes it the same way on the requesting side and on the verifying
  side, from the request it receives. Everything the service needs bound
  goes into the action: an RLN membership service folds in the identity
  commitment and the rate, an account registry the account and its
  operation.
- **`audience`** — the provider instance the payload is for, at most 255
  bytes, default `""`. The producer takes it from `args.audience`, the
  verifier from its operator's `config.audience`; when they differ the
  payload is refused, so a payload made for one provider does not work at
  another provider of the same service.

## 2. The contract

A vector module exposes one or both of two methods, each taking ONE
JSON-string argument and returning a JSON string:

| Method | Side | In | Out |
|---|---|---|---|
| `produce_auth` | requester | `{"auth_type","domain","action_hex","args"?}` | `{"payload_hex"}` |
| `verify_auth` | service | `{"auth_type","payload_hex","domain","action_hex","config"?,"peer_id"?}` | `{"ok","reason"?,"nullifier"?,"identity"?,"scheme"?}` |

- `auth_type` is `<scheme>-<authoriser>` (§3).
- `domain` is the service's domain (§1).
- `action_hex` is the action as 64 hex characters; one leading `0x`/`0X` and
  either case are accepted.
- `args` is the requesting application's opaque material, forwarded
  verbatim (it may arrive as a string holding a JSON object): the binding's
  `audience`, plus whatever the signer and the claimant need (a private key,
  a node URL, a claim locator).
- `config` is the service operator's configuration for this `auth_type`,
  passed on every call; verifiers keep no state between calls.
- `peer_id` is the requester's libp2p peer id as the service's transport
  authenticated it (read from the accepted stream). Only a scheme that signs
  nothing uses it (§4.4).

The verdict:

- A refusal is `{"ok": false, "reason": "…"}`, and is still a successful
  call.
- An accept is `{"ok": true, "identity", "scheme", "nullifier"}`: `identity`
  is the proven identity in its canonical form (what an allowlist holds, §3),
  `scheme` the scheme name that proved it. A caller parsing a verdict treats
  `identity`, `scheme` and `nullifier` as optional, since a verifier that is
  not a composed vector may omit them.
- A `nullifier` (any stable lowercase string naming the spent credential)
  opts the credential into the service's replay protection: reserved before
  the on-chain transaction, rolled back when nothing was submitted, persisted
  otherwise. The service keys it as `<scope>:<auth_type>:<nullifier>`
  (`namespaced_nullifier`), where `scope` is the service's own namespace (an
  RLN registry's config account, an account registry's id), so a credential
  is spent once per scope.

The `{"error": "…"}` envelope instead of a reply is for problems that are not
the requester's: a malformed request (bad JSON, a missing field, an invalid
`auth_type` or `domain`), an unknown or non-composing `auth_type`, and
operator or host mistakes (bad config, an unreachable node, no transport peer
id). Problems with what the requester supplied — the payload, or an action
that does not decode to 32 bytes — are refusals. On the produce side every
problem is an `{"error"}`.

## 3. Composition: `auth_type = <scheme>-<authoriser>`

An `auth_type` is two pieces joined by the FIRST dash, both lowercase
`[a-z0-9-]`; the scheme name has no dash. A **scheme** is how the digest gets
signed and which identity that proves. An **authoriser** is how an identity
gets accepted and what evidence that takes. A module composes the pieces it
ships into a registry and answers every `auth_type` whose halves exist and
are compatible; any other `auth_type` is an `{"error"}`.

| scheme | signs with | identity (`canonical`, what an allowlist holds) |
|---|---|---|
| `eth` | secp256k1 recoverable ECDSA over an EIP-191 text naming the domain and the digest (§4.3) | recovered address, lowercase `0x` + 40 hex |
| `lez` | BIP-340 Schnorr over the digest, by a LEZ public-account key (x-only) | LEE account id `sha256("/LEE/v0.3/AccountId/Public/\0\0\0\0\0" ‖ xonly)`, 64 hex (base58 accepted on input) |
| `logos` | a logos-blockchain node's zkSign (Groth16) over the digest, by its KMS key K | K, 64 hex little-endian Fr, a canonical scalar (as `/pow/status` prints it) |
| `keycard` | a Keycard's identity key, IDENTIFY_CARD with the digest as challenge | the card's compressed identity key, 66 hex |
| `peer` | nothing: the libp2p secure channel the request arrived on proved the requester's key (§4.4) | the peer id's multihash, lowercase hex (base58 `12D3Koo…`/`16Uiu2…` accepted on input) |

| authoriser | accepts | config | evidence bound | nullifier |
|---|---|---|---|---|
| `allowlist` | any scheme | `{"allowlist":[<identity>…],"audience"?:""}` | none | the identity |
| `any` | any scheme | `{"audience"?:""}` | none | the identity (once per identity per scope) |
| `attestation` | `keycard` | `{"trusted_cas":[<33-byte hex>…],"audience"?:""}` | none (the CA cert travels in the keycard part) | `keccak256(ident_pub)`, once per card |
| `pow-claim` | `logos` | `{"node_url","audience"?,"min_payout"?,"allow_direct_ownership"?,"allow_spend_locator"?,"http_timeout_ms"?,"audit_log"?}` | the claim locator; its `pow_nullifier` is in the digest | `hex(pow_nullifier)`, once per claim |

The twelve compositions `crates/auth-vectors` provides: `eth-allowlist`,
`eth-any`, `lez-allowlist`, `lez-any`, `logos-allowlist`, `logos-any`,
`logos-pow-claim`, `keycard-allowlist`, `keycard-any`,
`keycard-attestation`, `peer-allowlist`, `peer-any`. `eth-attestation` or
`lez-pow-claim` do not compose and are an `{"error"}`. `peer-any` is the
open-but-once vector: any libp2p peer may claim, once per peer id per scope,
with no key material on the requester beyond its libp2p identity.

## 4. The pipeline

Produce: parse `auth_type` → resolve signer and claimant → **binding** from
`domain`, `action_hex` and `args.audience` → **evidence** = the claimant
gathers it → **digest** (§4.1) → **scheme part** = the signer signs →
**payload** = scheme part ‖ evidence (§4.2).

Verify: parse `auth_type` → resolve scheme and authoriser → parse their
configs → **binding** from `domain`, `action_hex` and `config.audience` → hex
→ the scheme decodes its part (and names the identity it
claims, when the part carries a key) → the authoriser decodes its evidence
(nothing may follow it) → [authorise the claimed identity first, when the
authoriser asks for that: an allowlist lookup is cheaper than a signature
check] → **digest** → the scheme verifies the signature and yields the
PROVEN identity, which must equal the claimed one → [authorise the proven
identity otherwise] → accept with the proven identity, the scheme name and
the authoriser's nullifier.

### 4.1 The binding and its digest

```
Binding { domain:   string, 1..=64 bytes of [a-z0-9-]
          action:   32 bytes, opaque
          audience: string, at most 255 bytes, default "" }

D      = "logos/auth/" ‖ domain ‖ "/" ‖ auth_type     (ASCII)
digest = sha256( D
               ‖ action
               ‖ u8 len(audience) ‖ audience
               ‖ extra )               // the authoriser's bound evidence
```

`D` names both the service and the composition, so a signature made for one
`(domain, auth_type)` is never a signature for another; neither part can
contain `/`, so `D` cannot be read two ways. The length byte keeps
`audience ‖ extra` unambiguous. `extra` is empty for `allowlist`, `any` and
`attestation`; for `pow-claim` it is the 32-byte `pow_nullifier`.

Known answer: domain `rln-membership`, action `0x01 0x02 … 0x20`, audience
`""`, `lez-allowlist`, no extra →
`d1f956730b8338a3d79c3ab19a9b3454b5b3d9b4ba2b78c605f1faf349b023a8`.

### 4.2 The payload

```
payload = scheme part ‖ authoriser evidence
```

Each part is sized by its own decoder, and bytes left after the evidence
are refused. A payload may be empty: `peer` with `any` or `allowlist` has
neither a part nor evidence, so its `payload_hex` is `""`.

| scheme | part |
|---|---|
| `eth` | 65 B `r ‖ s ‖ recid` (recid 0/1 on produce; 27/28 also accepted on verify; low-S only) |
| `lez` | 96 B `xonly(32) ‖ BIP-340 sig(64)` |
| `logos` | 160 B `K(32) ‖ zksig(128)` (`pi_a ‖ pi_b ‖ pi_c`, compressed Groth16) |
| `keycard` | the IDENTIFY_CARD TLV `A0 { 8A cert(98) = ident_pub(33) ‖ ca_sig(65), DER sig }`, self-sized |
| `peer` | empty |

| authoriser | evidence |
|---|---|
| `allowlist`, `any`, `attestation` | none |
| `pow-claim` | `flags(1) ‖ claim_block_id(32) ‖ pow_nullifier(32) ‖ [spend_block_id(32) ‖ spend_tx_hash(32)]` (bit 0 of flags = spend locator present; the current verifier refuses it) |

A wallet signature or a card attestation made outside a producer module is
the scheme part as it stands; with an authoriser that binds no evidence it
is sent as the raw payload unchanged.

### 4.3 The eth scheme: a text a wallet can sign

`eth` signs the EIP-191 `personal_sign` envelope over the text

```
Logos <domain> authorisation: 0x<digest as 64 lowercase hex>
```

that is `keccak256("\x19Ethereum Signed Message:\n" ‖ decimal byte length of
the text ‖ text)`, with `digest` from §4.1. Any wallet can produce it
(`cast wallet sign --private-key … "<text>"`) and shows its user which service
the signature is for. The digest binds the domain, the auth type, the
action, the audience and the evidence exactly as for the other schemes. The
verifier rebuilds the text from the request's `domain` and the digest and
recovers the signer; under any other domain or action it recovers a
different address.

### 4.4 The peer scheme: the stream is the binding

`peer` signs nothing. The service accepts the request on a libp2p stream
whose Noise handshake proved that the remote holds the key behind its peer
id, and the request the service derives its action from arrives on that
same stream, so the transport ties the action to the identity. The verifier
is handed the peer id in `peer_id` and that is the proven identity. The
payload is empty: it binds neither domain, action nor audience, and cannot
be replayed from another peer, because the identity comes from
the transport, not from the payload. A service whose libp2p bridge reports
no peer id gets `{"error"}` (`transport peer id unavailable`), never an
accept.

## 5. Reasons

Written once in `auth_vector::reason`; the test suites match on them.

| reason | when |
|---|---|
| `signature verification failed[: <detail>]` | the scheme's signature does not verify |
| `<noun> not allowlisted: <identity>` | allowlist; noun = `address` / `account` / `public key` / `card` / `peer` |
| `payload names <claimed> but the signature proves <proven>` | the part's key and the signature disagree |
| `payload hex: …`, `payload has <n> trailing bytes` | the payload as a whole |
| `eth part must be 65 bytes …`, `lez part must be …`, `logos part must be …` | a scheme part too short |
| `action hex: …`, `action must be 32 bytes, got <n>` | the request's `action_hex` |
| `zkSign signature invalid (…)`, `public key is the zero key` | logos part |
| `attestation parse failed: …`, `attestation verification failed: …` | keycard part / CA |
| `evidence: …` | pow-claim locator |

Errors (`{"error"}`): `domain "<d>": expected 1 to 64 bytes of [a-z0-9-]`,
`auth_type "<t>": expected <scheme>-<authoriser>…`, `unknown auth_type
'<t>': …`, `verify_auth args: …` / `produce_auth args: …` (malformed JSON or
a missing field), `config.allowlist (array of …) is required`,
`config.allowlist is empty — nothing can verify`, `config.allowlist entries
must be strings`, a malformed entry named with its text,
`config.trusted_cas …`, `config.node_url is required`, `config.zksign_vk_path
…`, `transport peer id unavailable: …` (peer), and `node unreachable or
failing: …` from the pow-claim chain checks. On the produce side: `action_hex:
expected 64 hex chars (32 bytes), got …`, `audience: …`, and the signer's and
claimant's own messages.

## 6. Where the code is

| | |
|---|---|
| `crates/auth-vector` | the contract (§2): the JSON types and their borrowed `…Ref` twins, `parse_verdict` / `parse_produce_reply`, `namespaced_nullifier`; `AuthType`; `Binding`, `validate_domain`, `domain_separator`, `binding_digest` (§4.1); the `Scheme` / `Authoriser` / `Signer` / `Claimant` traits and the `Transport` context; the registries, `dispatch_verify` / `dispatch_produce` and the two flows (§4); the reasons (§5) |
| `crates/auth-vectors` | the pieces of §3 and their produce halves (feature `sign`; `keycard-pcsc` for the card over PC/SC) |
| `crates/keycard-attest`, `crates/keycard-client` | the keycard TLV, CA recovery and the PC/SC transport |
| `crates/zksign-light` | zkSign verification and the node's `/wallet/sign/zk` client |
| `crates/pow-claim` | claim discovery and the chain checks |

Operator guidance per scheme: `docs/auth-allowlists.md`; the pow-claim
design: `docs/auth-pow-claim.md`.
