use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crate::content_policy::{
    ContentPolicyEngine, Decision, ReasonCode, RequestMetadata, Rule, RuleAction, RuleSet,
};

const RELAY_PROTOCOL_HASH_FNV1A_64: u64 = 0x4bd0_588c_8db3_0d29;
const TRANSPORT_ADAPTER_HASH_FNV1A_64: u64 = 0x30a5_e935_3ff4_9642;
const SSH_TRANSPORT_ADAPTER_HASH_FNV1A_64: u64 = 0x1d2d_7376_d8e3_6905;

#[test]
fn relay_protocol_code_unchanged() {
    assert_file_hash(
        "src/relay_protocol.rs",
        RELAY_PROTOCOL_HASH_FNV1A_64,
        "relay protocol code changed",
    );
}

#[test]
fn transport_adapters_code_unchanged() {
    assert_file_hash(
        "src/transport_adapter.rs",
        TRANSPORT_ADAPTER_HASH_FNV1A_64,
        "transport adapter code changed",
    );
    assert_file_hash(
        "src/ssh_transport_adapter.rs",
        SSH_TRANSPORT_ADAPTER_HASH_FNV1A_64,
        "ssh transport adapter code changed",
    );
}

#[test]
fn same_request_same_rules_same_result() {
    let mut headers = BTreeMap::new();
    headers.insert("User-Agent".to_string(), "EBT-Test".to_string());
    let request = RequestMetadata::new(
        "GET".to_string(),
        "https://tracker.example.com/pixel".to_string(),
        "tracker.example.com".to_string(),
        443,
        headers,
    );

    let rules = RuleSet::new(vec![
        Rule::DomainSuffix {
            suffix: "example.com".to_string(),
            action: RuleAction::Block(ReasonCode::Tracking),
        },
        Rule::DomainExact {
            domain: "tracker.example.com".to_string(),
            action: RuleAction::Allow,
        },
    ]);
    let engine = ContentPolicyEngine::new(rules);

    let first = engine.evaluate(&request);
    let second = engine.evaluate(&request);
    let third = engine.evaluate(&request);

    assert_eq!(
        first,
        Decision::Block {
            reason: ReasonCode::Tracking
        }
    );
    assert_eq!(first, second);
    assert_eq!(second, third);
}

fn assert_file_hash(path: &str, expected: u64, message: &str) {
    let mut full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    full_path.push(path);
    let bytes = fs::read(&full_path).expect("failed to read file for hash check");
    let hash = fnv1a_64(&bytes);
    assert_eq!(hash, expected, "{message}: {}", full_path.display());
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}
