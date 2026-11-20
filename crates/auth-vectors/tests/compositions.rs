use std::sync::Mutex;

use auth_vector::{
    binding_digest, dispatch_produce, dispatch_verify, parse_verdict, reason, AuthType, Authoriser,
    Binding, Identity, Outcome, ProduceRegistry, ProduceRequestRef, Signer, Verdict,
    VerifyRegistry, VerifyRequestRef,
};
use auth_vectors::authoriser::{Allowlist, Any, Attestation, PowClaim};
use auth_vectors::claimant::{AllowlistClaimant, AnyClaimant, AttestationClaimant, PowClaimant};
use auth_vectors::scheme::keycard::KeycardIdentity;
use auth_vectors::scheme::peer::parse_peer_id;
use auth_vectors::scheme::{Eth, Keycard, Lez, Logos, Peer};
use auth_vectors::signer::{EthSigner, LezSigner, LogosSigner, PeerSigner, StaticKey};
use pow_claim::node::testing::FakeNode;
use pow_claim::NodeApi;
use serde_json::{json, Value};
use zksign_light::ZkNode;

const DOMAIN: &str = "rln-membership";
const OTHER_DOMAIN: &str = "account-registry";
const ACTION: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const OTHER_ACTION: &str = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";
const PK42: [u8; 32] = [0x42; 32];
const ADDR42: &str = "0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025";
const CAST_SIG: &str = "70dc76365127faabdef609b0c82f832147ea39badb276f36146c8a163c58a904248ead70f40d74ff25b835b7f7fe21c638db77590f5aad5e7e362dda85c4c3291c";
const PK0_ACCT_HEX: &str = "ec2cbcd4488075c4b30678c30351327fdf99f3fe703edc2999b68f8fd12bdbc8";
const PK0_ACCT_B58: &str = "GtvnQVLsv8V34E3X9hMBR9hsUokapUgiE4o7vCU4VMB5";
const K: &str = "e3635f207984ae779cf76b5f20714b514373f61ff96260879fe0a6d71f2dce07";
const GOLDEN_TLV: &str = "a081ab8a620365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a11188ada267db3312a84e1be27c01c736a89da7a1fe4f7e90ce297e74f00008e2bfdb06058374abfc1c026386d16ead7bbc19bc0645d2e7acf7b953169bbc1ac0130450220364c5ca937b7ca42861978f086d206cc569ef0bb2ea4c7de08929c2fcca7434d022100c87699ce4f977e6a7a4800343db9b6842b91ca873e56dfe3327d19a2d01af14e";
const TEST_CA: &str = "02fc929321aa94fea085b166994aa66590116252cf0235a03accaa2c8ab4595de5";
const IDENT_PUB: &str = "0365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a";
const PEER_B58: &str = "16Uiu2HAkyiMKmjcAj4FS5jot1jMZB73mnY3wJnSTKZmTBhrFJEaT";
const OTHER_PEER_B58: &str = "12D3KooWA1yXQfKD3c8QznGkpf1ZepPH1FQKwAwMxbTh1feQsapZ";

struct FakeZk;
impl ZkNode for FakeZk {
    fn pow_status(&self) -> Result<Value, String> {
        Ok(json!({ "auto_claim": { "targets": [{ "public_key": K }] } }))
    }
    fn sign_zk(&self, digest: &[u8; 32], _pk_hex: &str) -> Result<[u8; 128], String> {
        Ok(fake_zksig(digest))
    }
}

fn fake_zksig(digest: &[u8; 32]) -> [u8; 128] {
    let mut sig = [0x11; 128];
    sig[..32].copy_from_slice(digest);
    sig
}

struct GoldenCard;
impl Signer for GoldenCard {
    fn scheme(&self) -> &'static str {
        "keycard"
    }
    fn sign(
        &self,
        _b: &Binding,
        _digest: &[u8; 32],
        _args: Option<&Value>,
    ) -> Result<Vec<u8>, String> {
        hex::decode(GOLDEN_TLV).map_err(|e| e.to_string())
    }
    fn identity(&self, _args: Option<&Value>) -> Result<Box<dyn Identity>, String> {
        let tlv = hex::decode(GOLDEN_TLV).map_err(|e| e.to_string())?;
        let att = keycard_attest::attest::parse_attestation(&tlv).map_err(|e| e.to_string())?;
        Ok(Box::new(KeycardIdentity {
            ident_pub: att.ident_pub,
            ca_sig: att.ca_sig,
        }))
    }
}

struct ChainFixture(Mutex<FakeNode>);
impl ChainFixture {
    fn load() -> Self {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../pow-claim/tests/fixtures/synthetic");
        ChainFixture(Mutex::new(FakeNode::from_dir(dir).unwrap()))
    }
    fn node(&self) -> std::sync::MutexGuard<'_, FakeNode> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
impl NodeApi for ChainFixture {
    fn pow_status(&self) -> Result<Value, String> {
        self.node().pow_status()
    }
    fn info(&self) -> Result<Value, String> {
        self.node().info()
    }
    fn block(&self, id_hex: &str) -> Result<Option<Value>, String> {
        self.node().block(id_hex)
    }
    fn immutable_blocks(&self, slot_from: u64, slot_to: u64) -> Result<Vec<Value>, String> {
        self.node().immutable_blocks(slot_from, slot_to)
    }
    fn events(&self, id_hex: &str) -> Result<Vec<Value>, String> {
        self.node().events(id_hex)
    }
    fn sign_zk(&self, digest: &[u8; 32], pk_hex: &str) -> Result<[u8; 128], String> {
        self.node().sign_zk(digest, pk_hex)
    }
}

fn sk3() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = 3;
    b
}

fn verifiers() -> VerifyRegistry {
    VerifyRegistry::new()
        .scheme(Eth)
        .scheme(Lez)
        .scheme(Logos)
        .scheme(Keycard)
        .scheme(Peer)
        .authoriser(Allowlist)
        .authoriser(Any)
        .authoriser(Attestation)
        .authoriser(PowClaim)
}

fn producers() -> ProduceRegistry {
    ProduceRegistry::new()
        .signer(EthSigner(Box::new(StaticKey(PK42))))
        .signer(LezSigner(Box::new(StaticKey(sk3()))))
        .signer(LogosSigner {
            node: Some(Box::new(FakeZk)),
        })
        .signer(GoldenCard)
        .signer(PeerSigner)
        .claimant(AllowlistClaimant)
        .claimant(AnyClaimant)
        .claimant(AttestationClaimant)
        .claimant(PowClaimant {
            node: Some(Box::new(ChainFixture::load())),
        })
}

fn produce_in(auth_type: &str, domain: &str, action_hex: &str, args: &Value) -> Value {
    let req = ProduceRequestRef {
        auth_type,
        domain,
        action_hex,
        args: Some(args),
    };
    let out = dispatch_produce(&serde_json::to_string(&req).unwrap(), &producers());
    serde_json::from_str(&out).unwrap()
}

fn produce(auth_type: &str, args: &Value) -> String {
    payload_of(&produce_in(auth_type, DOMAIN, ACTION, args))
}

fn payload_of(reply: &Value) -> String {
    reply["payload_hex"]
        .as_str()
        .unwrap_or_else(|| panic!("{reply}"))
        .to_string()
}

fn verify_in(
    auth_type: &str,
    payload_hex: &str,
    domain: &str,
    action_hex: &str,
    config: &Value,
    peer_id: Option<&str>,
) -> Value {
    let req = VerifyRequestRef {
        auth_type,
        payload_hex,
        domain,
        action_hex,
        config: Some(config),
        peer_id,
    };
    let out = dispatch_verify(&serde_json::to_string(&req).unwrap(), &verifiers());
    serde_json::from_str(&out).unwrap()
}

fn verify(auth_type: &str, payload_hex: &str, config: &Value) -> Value {
    verify_in(auth_type, payload_hex, DOMAIN, ACTION, config, None)
}

fn verify_from(auth_type: &str, payload_hex: &str, config: &Value, peer_id: &str) -> Value {
    verify_in(
        auth_type,
        payload_hex,
        DOMAIN,
        ACTION,
        config,
        Some(peer_id),
    )
}

fn reason_of(v: &Value) -> &str {
    v["reason"]
        .as_str()
        .unwrap_or_else(|| panic!("no reason: {v}"))
}

const TWELVE: [&str; 12] = [
    "eth-allowlist",
    "eth-any",
    "lez-allowlist",
    "lez-any",
    "logos-allowlist",
    "logos-any",
    "logos-pow-claim",
    "keycard-allowlist",
    "keycard-any",
    "keycard-attestation",
    "peer-allowlist",
    "peer-any",
];

#[test]
fn the_registries_compose_exactly_the_twelve_vectors() {
    assert_eq!(verifiers().auth_types(), TWELVE);
    assert_eq!(producers().auth_types(), TWELVE);
}

type Case<'a> = (
    &'a str,
    Value,
    Value,
    Option<&'a str>,
    Result<&'a str, &'a str>,
);

#[test]
fn every_composition_produces_and_verifies() {
    let peer_hex = parse_peer_id(PEER_B58).unwrap();
    let chain_cfg =
        json!({ "node_url": "http://127.0.0.1:1", "audience": "poc", "http_timeout_ms": 300 });
    let cases: [Case<'_>; 12] = [
        (
            "eth-allowlist",
            json!({}),
            json!({ "allowlist": [ADDR42] }),
            None,
            Ok(ADDR42),
        ),
        ("eth-any", json!({}), json!({}), None, Ok(ADDR42)),
        (
            "lez-allowlist",
            json!({}),
            json!({ "allowlist": [PK0_ACCT_B58] }),
            None,
            Ok(PK0_ACCT_HEX),
        ),
        ("lez-any", json!({}), json!({}), None, Ok(PK0_ACCT_HEX)),
        (
            "logos-allowlist",
            json!({}),
            json!({ "allowlist": [K] }),
            None,
            Err("zkSign signature invalid"),
        ),
        (
            "logos-any",
            json!({}),
            json!({}),
            None,
            Err("zkSign signature invalid"),
        ),
        (
            "logos-pow-claim",
            json!({ "audience": "poc" }),
            chain_cfg,
            None,
            Err("zkSign signature invalid"),
        ),
        (
            "keycard-allowlist",
            json!({}),
            json!({ "allowlist": [IDENT_PUB] }),
            None,
            Err("attestation verification failed"),
        ),
        (
            "keycard-any",
            json!({}),
            json!({}),
            None,
            Err("attestation verification failed"),
        ),
        (
            "keycard-attestation",
            json!({}),
            json!({ "trusted_cas": [TEST_CA] }),
            None,
            Err("attestation verification failed"),
        ),
        (
            "peer-allowlist",
            json!({}),
            json!({ "allowlist": [PEER_B58] }),
            Some(PEER_B58),
            Ok(&peer_hex),
        ),
        (
            "peer-any",
            json!({}),
            json!({}),
            Some(PEER_B58),
            Ok(&peer_hex),
        ),
    ];
    assert!(
        cases.iter().map(|c| c.0).eq(TWELVE),
        "one case per composition"
    );
    for (auth_type, args, config, peer, want) in &cases {
        let payload = produce(auth_type, args);
        let v = verify_in(auth_type, &payload, DOMAIN, ACTION, config, *peer);
        let verdict = parse_verdict(&v).unwrap_or_else(|e| panic!("{auth_type}: {e}"));
        let scheme = AuthType::parse(auth_type).unwrap().scheme;
        match want {
            Ok(id) => assert_eq!(
                verdict,
                Verdict::accept(*id, scheme, Some(id.to_string())),
                "{auth_type}"
            ),
            Err(prefix) => {
                assert!(!verdict.ok, "{auth_type}: {v}");
                assert!(reason_of(&v).contains(prefix), "{auth_type}: {v}");
            }
        }
    }
}

#[test]
fn a_payload_for_one_service_is_refused_by_another() {
    let cfg = json!({ "allowlist": [ADDR42] });
    let p = produce("eth-allowlist", &json!({}));
    let v = verify_in("eth-allowlist", &p, OTHER_DOMAIN, ACTION, &cfg, None);
    assert!(
        reason_of(&v).starts_with("address not allowlisted: 0x"),
        "{v}"
    );
    assert!(!reason_of(&v).contains(ADDR42), "{v}");
    let v = verify_in(
        "eth-any",
        &produce("eth-any", &json!({})),
        OTHER_DOMAIN,
        ACTION,
        &json!({}),
        None,
    );
    assert_ne!(v["identity"], ADDR42, "{v}");
}

#[test]
fn changing_the_action_after_signing_is_refused() {
    let p = produce("eth-allowlist", &json!({}));
    let v = verify_in(
        "eth-allowlist",
        &p,
        DOMAIN,
        OTHER_ACTION,
        &json!({ "allowlist": [ADDR42] }),
        None,
    );
    assert!(reason_of(&v).starts_with("address not allowlisted"), "{v}");
    assert!(!reason_of(&v).contains(ADDR42), "{v}");

    let p = produce("logos-any", &json!({}));
    let v = verify_in("logos-any", &p, DOMAIN, &"zz".repeat(32), &json!({}), None);
    assert!(reason_of(&v).starts_with("action hex:"), "{v}");
    let v = verify_in("logos-any", &p, DOMAIN, &ACTION[..62], &json!({}), None);
    assert_eq!(reason_of(&v), "action must be 32 bytes, got 31");
}

#[test]
fn peer_any_is_the_transports_identity_once_per_peer() {
    let payload = produce("peer-any", &json!({}));
    assert_eq!(payload, "");
    let hexid = parse_peer_id(PEER_B58).unwrap();

    let v = verify_from("peer-any", &payload, &json!({}), PEER_B58);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(
        (&v["nullifier"], &v["identity"], &v["scheme"]),
        (&json!(hexid), &json!(hexid), &json!("peer"))
    );
    let v = verify_from("peer-any", &payload, &json!({}), OTHER_PEER_B58);
    assert_eq!(v["nullifier"], parse_peer_id(OTHER_PEER_B58).unwrap());
    let v = verify("peer-any", &payload, &json!({}));
    assert_eq!(v["error"], reason::TRANSPORT_PEER_UNKNOWN);
    let v = verify_from("peer-any", "00", &json!({}), PEER_B58);
    assert_eq!(reason_of(&v), "payload has 1 trailing bytes");
    let v = verify(
        "eth-any",
        &produce("eth-any", &json!({})),
        &json!({ "audience": "" }),
    );
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["nullifier"], ADDR42);
}

#[test]
fn peer_allowlist_lists_peer_ids_in_either_spelling() {
    let payload = "";
    let hexid = parse_peer_id(PEER_B58).unwrap();
    for entry in [PEER_B58.to_string(), hexid.to_uppercase()] {
        let v = verify_from(
            "peer-allowlist",
            payload,
            &json!({ "allowlist": [entry] }),
            PEER_B58,
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["nullifier"], hexid);
    }
    let v = verify_from(
        "peer-allowlist",
        payload,
        &json!({ "allowlist": [OTHER_PEER_B58] }),
        PEER_B58,
    );
    assert_eq!(reason_of(&v), format!("peer not allowlisted: {hexid}"));
    let v = verify_from(
        "peer-allowlist",
        payload,
        &json!({ "allowlist": ["zz"] }),
        PEER_B58,
    );
    assert!(v["error"].as_str().unwrap().contains("'zz'"), "{v}");
}

#[test]
fn eth_allowlist_round_trips_and_matches_foundry() {
    let payload = produce("eth-allowlist", &json!({}));
    let v = verify(
        "eth-allowlist",
        &payload,
        &json!({ "allowlist": [ADDR42.to_uppercase().replace("0X", "0x")] }),
    );
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(
        (&v["nullifier"], &v["identity"], &v["scheme"]),
        (&json!(ADDR42), &json!(ADDR42), &json!("eth"))
    );

    let cast = hex::decode(CAST_SIG).unwrap();
    let produced = hex::decode(&payload).unwrap();
    assert_eq!(
        cast[..64],
        produced[..64],
        "the producer signs what cast signs (r ‖ s)"
    );
    assert_eq!(cast[64], produced[64] + 27, "cast's v is 27 + recid");
    let v = verify(
        "eth-allowlist",
        &format!("0x{CAST_SIG}"),
        &json!({ "allowlist": [ADDR42] }),
    );
    assert_eq!(v["ok"], true, "{v}");
    let v = verify(
        "eth-allowlist",
        &payload,
        &json!({ "allowlist": [ADDR42], "audience": "x" }),
    );
    assert!(reason_of(&v).starts_with("address not allowlisted"), "{v}");

    let v = verify(
        "eth-allowlist",
        &payload,
        &json!({ "allowlist": ["0x0000000000000000000000000000000000000001"] }),
    );
    assert_eq!(reason_of(&v), format!("address not allowlisted: {ADDR42}"));
    let v = verify("eth-allowlist", &payload, &json!({ "allowlist": [] }));
    assert_eq!(v["error"], reason::ALLOWLIST_EMPTY);
    let v = verify("eth-allowlist", &payload, &json!({}));
    assert!(v["error"].as_str().unwrap().contains("required"), "{v}");
    let v = verify(
        "eth-allowlist",
        &payload,
        &json!({ "allowlist": ["0x1234"] }),
    );
    assert!(v["error"].as_str().unwrap().contains("\"0x1234\""), "{v}");
}

#[test]
fn lez_allowlist_round_trips_with_hex_or_base58_entries() {
    let payload = produce("lez-allowlist", &json!({ "audience": "provider-1" }));
    for entry in [PK0_ACCT_HEX, PK0_ACCT_B58] {
        let v = verify(
            "lez-allowlist",
            &payload,
            &json!({ "allowlist": [entry], "audience": "provider-1" }),
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(
            (&v["nullifier"], &v["identity"], &v["scheme"]),
            (&json!(PK0_ACCT_HEX), &json!(PK0_ACCT_HEX), &json!("lez"))
        );
    }
    let v = verify(
        "lez-allowlist",
        &payload,
        &json!({ "allowlist": [PK0_ACCT_HEX], "audience": "other" }),
    );
    assert_eq!(reason_of(&v), reason::SIG_FAILED);
    let v = verify(
        "lez-allowlist",
        &payload,
        &json!({ "allowlist": ["00".repeat(32)], "audience": "provider-1" }),
    );
    assert!(reason_of(&v).starts_with("account not allowlisted"), "{v}");
}

#[test]
fn logos_allowlist_checks_the_key_before_the_proof() {
    let payload = produce("logos-allowlist", &json!({}));
    assert_eq!(&payload[..64], K, "K leads the part");
    let t = AuthType::parse("logos-allowlist").unwrap();
    let b = Binding {
        domain: DOMAIN.into(),
        action: hex::decode(ACTION).unwrap().try_into().unwrap(),
        audience: String::new(),
    };
    assert_eq!(&payload[64..128], hex::encode(binding_digest(&t, &b, &[])));
    let v = verify("logos-allowlist", &payload, &json!({ "allowlist": [K] }));
    assert!(reason_of(&v).contains("zkSign signature invalid"), "{v}");
    let v = verify(
        "logos-allowlist",
        &payload,
        &json!({ "allowlist": [hex::encode(zksign_light::zero_pk_le())] }),
    );
    assert_eq!(reason_of(&v), format!("public key not allowlisted: {K}"));
    let v = verify(
        "logos-allowlist",
        &payload,
        &json!({ "allowlist": ["ff".repeat(32)] }),
    );
    assert!(
        v["error"].as_str().unwrap().contains("big-endian paste"),
        "{v}"
    );
    let v = verify(
        "logos-allowlist",
        &payload,
        &json!({ "allowlist": [K], "zksign_vk_path": "/nonexistent/vk.json" }),
    );
    assert!(
        v["error"].as_str().unwrap().contains("zksign_vk_path"),
        "{v}"
    );
}

#[test]
fn logos_pow_claim_binds_the_claim_nullifier_and_needs_the_logos_scheme() {
    let claim = pow_claim::gather(
        &*ChainFixture::load().node(),
        &pow_claim::ProduceArgs::parse(Some(&json!({ "audience": "poc" }))).unwrap(),
    )
    .unwrap();
    assert_eq!(hex::encode(claim.k), K);
    let evidence = claim.evidence.encode();

    let t = AuthType::parse("logos-pow-claim").unwrap();
    let b = Binding {
        domain: DOMAIN.into(),
        action: hex::decode(ACTION).unwrap().try_into().unwrap(),
        audience: "poc".into(),
    };
    let digest = binding_digest(&t, &b, &claim.evidence.pow_nullifier);
    let mut part = claim.k.to_vec();
    part.extend_from_slice(&FakeZk.sign_zk(&digest, K).unwrap());
    let payload = hex::encode([&part[..], &evidence].concat());
    assert_eq!(
        produce("logos-pow-claim", &json!({ "audience": "poc" })),
        payload,
        "the producer sends K ‖ zksig(digest) ‖ evidence"
    );

    let cfg =
        json!({ "node_url": "http://127.0.0.1:1", "audience": "poc", "http_timeout_ms": 300 });
    let v = verify("logos-pow-claim", &payload, &cfg);
    assert!(
        reason_of(&v).contains("zkSign signature invalid"),
        "evidence decoded, digest bound, proof refused: {v}"
    );
    let v = verify("logos-pow-claim", &payload, &json!({ "audience": "poc" }));
    assert!(v["error"].as_str().unwrap().contains("node_url"), "{v}");
    let short = hex::encode([&part[..], &evidence[..10]].concat());
    let v = verify("logos-pow-claim", &short, &cfg);
    assert!(reason_of(&v).starts_with("evidence:"), "{v}");

    let v = verify("eth-pow-claim", &payload, &json!({}));
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("does not accept the eth scheme"),
        "{v}"
    );
    let out = produce_in("lez-pow-claim", DOMAIN, ACTION, &json!({}));
    assert!(
        out["error"]
            .as_str()
            .unwrap()
            .contains("does not accept the lez scheme"),
        "{out}"
    );
}

#[test]
fn keycard_allowlist_judges_the_card_before_its_signature() {
    let payload = produce("keycard-allowlist", &json!({}));
    assert_eq!(payload, GOLDEN_TLV);
    let v = verify(
        "keycard-allowlist",
        &payload,
        &json!({ "allowlist": [TEST_CA] }),
    );
    assert_eq!(reason_of(&v), format!("card not allowlisted: {IDENT_PUB}"));
    let v = verify(
        "keycard-allowlist",
        &payload,
        &json!({ "allowlist": [IDENT_PUB] }),
    );
    assert!(
        reason_of(&v).starts_with("attestation verification failed"),
        "{v}"
    );
    let v = verify(
        "keycard-allowlist",
        "a0",
        &json!({ "allowlist": [IDENT_PUB] }),
    );
    assert!(reason_of(&v).starts_with("attestation parse failed"), "{v}");
}

#[test]
fn attestation_trusts_the_ca_that_signed_the_card_key() {
    let att = keycard_attest::attest::parse_attestation(&hex::decode(GOLDEN_TLV).unwrap()).unwrap();
    let id = KeycardIdentity {
        ident_pub: att.ident_pub,
        ca_sig: att.ca_sig,
    };
    let cfg = Attestation
        .config(
            &Keycard,
            Some(&json!({ "trusted_cas": [TEST_CA], "audience": "x" })),
        )
        .unwrap();
    assert_eq!(Attestation.audience(cfg.as_ref()), "x");
    assert!(matches!(
        Attestation.authorise(cfg.as_ref(), &id, &()).unwrap(),
        Outcome::Ok(())
    ));
    assert_eq!(
        Attestation.nullifier(&id, &()),
        hex::encode(keycard_attest::attest::nullifier(&att.ident_pub))
    );
    let other = Attestation
        .config(
            &Keycard,
            Some(&json!({ "trusted_cas": [format!("02{}", "11".repeat(32))] })),
        )
        .unwrap();
    let Outcome::Reject(r) = Attestation.authorise(other.as_ref(), &id, &()).unwrap() else {
        panic!()
    };
    assert!(r.contains("CA is not trusted"), "{r}");
    assert!(Attestation
        .config(&Keycard, Some(&json!({ "trusted_cas": [] })))
        .unwrap_err()
        .contains("empty"));
    assert!(Attestation
        .config(&Keycard, None)
        .unwrap_err()
        .contains("required"));
    assert!(!Attestation.accepts("eth") && Attestation.accepts("keycard"));
    let v = verify(
        "keycard-attestation",
        &produce("keycard-attestation", &json!({})),
        &json!({ "trusted_cas": [TEST_CA] }),
    );
    assert!(
        reason_of(&v).starts_with("attestation verification failed"),
        "{v}"
    );
    let v = verify("eth-attestation", "", &json!({ "trusted_cas": [TEST_CA] }));
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("does not accept the eth scheme"),
        "{v}"
    );
    assert_eq!(id.canonical(), IDENT_PUB);
}
