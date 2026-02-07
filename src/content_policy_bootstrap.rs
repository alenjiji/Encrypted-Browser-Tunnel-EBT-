use std::fs;

use crate::config::ProxyPolicy;
use crate::content_policy::{ruleset_from_easylist, ContentPolicyEngine, RuleSet};

pub fn build_content_policy_engine(policy: &ProxyPolicy) -> (ContentPolicyEngine, bool) {
    if !policy.content_policy_enabled {
        return (ContentPolicyEngine::new(RuleSet::default()), false);
    }

    let Some(path) = policy.content_policy_rules.as_ref() else {
        return (ContentPolicyEngine::new(RuleSet::default()), true);
    };

    let rules_text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => {
            return (ContentPolicyEngine::new(RuleSet::default()), true);
        }
    };

    let ruleset = ruleset_from_easylist(&rules_text);
    (ContentPolicyEngine::new(ruleset), true)
}
