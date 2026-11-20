# logos-membership-allocation-crates

Rust crates behind the RLN membership allocator, its client and the auth producer modules. No Logos
Core module lives here; the modules do:
[`logos-membership-allocation-module`](https://github.com/logos-co/logos-membership-allocation-module)
(the allocator, which verifies the auth vectors),
[`logos-membership-allocation-client-module`](https://github.com/logos-co/logos-membership-allocation-client-module)
(the client), `logos-rln-sign-module` and `logos-keycard-capture-module` (the producers).

The `paymaster_*` crates serve any service that submits a program interaction on behalf of an
authenticated user, and its client; `membership_allocation_action` is the RLN membership
registration they carry.

| Crate | What it is |
|---|---|
| `membership_allocation_action` | The membership registration as the paymaster envelope carries it: the protocol id `/logos/paymaster/rln-membership/1.0.0`, the action kind, the auth domain `rln-membership`, the action bytes (commitment and optional rate), the commitment check both sides apply, and the grant. |
| `paymaster_lp` | A raw `lp_*` cross-module client with per-call timeouts, an owner-thread client cache, and the `CallError` classification of whether a failed call may have run. |
| `paymaster_wire` | The request and response messages every service speaks (`envelope`), the advertisement data codec, account canonicalisation and the protobuf codec they are written with. |
| `paymaster_service` | The provider side: `Engine` runs advertisement, the serialized request worker, the auth gate and credential replay protection for a `Service`. The gate verifies the vectors the service gives it (`Engine::with_vectors`) in process and asks a verifier module for any other. |
| `paymaster_client` | The requesting side: provider discovery, auth payload production and the ask-in-turn loop for a `ClientAction`. |
| `auth_vector` | The auth contract: produce/verify JSON shapes, the signed binding, the scheme × authoriser composition and registries. |
| `auth_vectors` | The pieces: eth, lez, logos, keycard and peer schemes; allowlist, any, attestation and pow-claim authorisers; produce halves behind feature `sign`. |
| `pow-claim` | The pow-claim authoriser: claim discovery (`produce`) and chain checks (`verify`). |
| `zksign_light` | zkSign Groth16 verification (`verify`) and the node's `/wallet/sign/zk` client (`client`). |
| `keycard_attest` | Keycard IDENTIFY_CARD parsing, challenge signature and CA recovery. |
| `keycard_client` | PC/SC keycard transport. |

`docs/auth-vectors.md` is normative for the auth contract.

## Consuming

Git dependency pinned by commit, one rev for the whole workspace:

```toml
[dependencies]
membership_allocation_action = { git = "https://github.com/logos-co/logos-membership-allocation-crates", rev = "<commit>" }
paymaster_wire = { git = "https://github.com/logos-co/logos-membership-allocation-crates", rev = "<commit>" }

[dev-dependencies]
paymaster_lp = { git = "https://github.com/logos-co/logos-membership-allocation-crates", rev = "<commit>", features = ["test-fake"] }
```

`test-fake` replaces the `lp_*` bindings with stubs and exposes `fake`, a scripted stand-in for
every cross-module call. Enable it from `[dev-dependencies]` only, with `resolver = "2"`: a build
with the feature on links no real `lp_*` symbol.

A change to a `pub` item needs a new rev in every consumer.

## Checks

```sh
cargo fmt --all --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
