# auth_vector

Contract kit for **auth vectors** — the pluggable strategies that authorise
an action a service submits on chain for a requester (an RLN membership
allocation, an account-registry operation). Import this crate to build a
vector module that any service and any application can use with
configuration only. The normative description of the contract,
the composition rule, the binding digest, the payload layout and the reasons
is [`docs/auth-vectors.md`](../../docs/auth-vectors.md); this crate is its
Rust form.

## What is here

- `types`: the two methods' JSON shapes (`ProduceRequest` / `ProduceReply`,
  `VerifyRequest` / `Verdict`, and the borrowed `…Ref` request twins), the
  caller-side parsers, and `namespaced_nullifier`.
- `AuthType`: `<scheme>-<authoriser>`, split at the first dash.
- `Binding` (service `domain`, 32-byte `action` digest, `audience`) +
  `binding_digest`: what gets signed, under the domain separator
  `logos/auth/<domain>/<auth_type>`. The payload is
  `scheme part ‖ evidence`.
- `pieces`: the `Scheme` / `Authoriser` (verify side) and `Signer` /
  `Claimant` (produce side) traits, `Identity`, and `Outcome` (a reject) vs
  `Err` (an operator mistake).
- `registry`: `VerifyRegistry` / `ProduceRegistry` compose the pieces a module
  ships and answer every composition that exists; `dispatch_verify` /
  `dispatch_produce` are the module-method glue.
- `flow`: `verify_flow` and `produce_flow`, the one pipeline.
- `reason`: the reject strings, written once.

## Building a module

```rust
use auth_vector::{dispatch_verify, VerifyRegistry};
use auth_vectors::authoriser::Allowlist;
use auth_vectors::scheme::{Eth, Lez};

fn registry() -> VerifyRegistry {
    VerifyRegistry::new().scheme(Eth).scheme(Lez).authoriser(Allowlist)
    // answers "eth-allowlist" and "lez-allowlist"
}

fn verify_auth(&mut self, args_json: String) -> String {
    dispatch_verify(&args_json, &registry())
}
```

A new scheme implements `Scheme` (and `Signer` for its produce half); a new
authoriser implements `Authoriser` (and `Claimant`); neither needs a name
registered anywhere — the composition is the name. `crates/auth-vectors`
holds the reference pieces.

## Wiring it up (configuration only)

- **Service** — the `serve` args of a service
  (`membership_allocation_module.serve`, the account registry service's
  `serve`):
  `"authVerifiers": {"eth-allowlist": {"module": "<verifier module>", "config": {…}}}`.
  A service that verifies the vector itself (`membership_allocation_module`
  does, for every composition of `crates/auth-vectors`) takes the entry
  without `module`.
- **Requester** — the `request` args of its client
  (`membership_allocation_client_module.request`, the account registry
  client's `request`): `"authType"` plus `"authPayload"` (the payload hex)
  or `"authProvider": "<producer module>"`, with `"authArgs"` forwarded to
  the producer.
- The host application declares its chosen vector modules in its
  `metadata.json` dependencies so they get installed and loaded.
