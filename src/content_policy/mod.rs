use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMetadata {
    pub method: String,
    pub full_url: String,
    pub host: String,
    pub port: u16,
    headers: BTreeMap<String, String>,
}

impl RequestMetadata {
    pub fn new(
        method: String,
        full_url: String,
        host: String,
        port: u16,
        headers: BTreeMap<String, String>,
    ) -> Self {
        Self {
            method,
            full_url,
            host,
            port,
            headers,
        }
    }

    pub fn headers(&self) -> &BTreeMap<String, String> {
        &self.headers
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block { reason: ReasonCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    Ads,
    Tracking,
    Custom,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    DomainExact {
        domain: String,
        action: RuleAction,
    },
    DomainSuffix {
        suffix: String,
        action: RuleAction,
    },
    UrlPrefix {
        prefix: String,
        action: RuleAction,
    },
    HeaderEquals {
        name: String,
        value: String,
        action: RuleAction,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Block(ReasonCode),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn evaluate(&self, request: &RequestMetadata) -> Option<Decision> {
        for rule in &self.rules {
            if rule_matches(rule, request) {
                return Some(rule_action_to_decision(rule_action(rule)));
            }
        }
        None
    }
}

fn rule_action(rule: &Rule) -> RuleAction {
    match rule {
        Rule::DomainExact { action, .. } => *action,
        Rule::DomainSuffix { action, .. } => *action,
        Rule::UrlPrefix { action, .. } => *action,
        Rule::HeaderEquals { action, .. } => *action,
    }
}

fn rule_action_to_decision(action: RuleAction) -> Decision {
    match action {
        RuleAction::Allow => Decision::Allow,
        RuleAction::Block(reason) => Decision::Block { reason },
    }
}

fn rule_matches(rule: &Rule, request: &RequestMetadata) -> bool {
    match rule {
        Rule::DomainExact { domain, .. } => request.host == *domain,
        Rule::DomainSuffix { suffix, .. } => host_matches_suffix(&request.host, suffix),
        Rule::UrlPrefix { prefix, .. } => request.full_url.starts_with(prefix),
        Rule::HeaderEquals { name, value, .. } => {
            match request.headers().get(name) {
                Some(header_value) => header_value == value,
                None => false,
            }
        }
    }
}

fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    if host == suffix {
        return true;
    }
    let host_len = host.len();
    let suffix_len = suffix.len();
    if host_len <= suffix_len {
        return false;
    }
    if !host.ends_with(suffix) {
        return false;
    }
    let dot_index = host_len - suffix_len - 1;
    host.as_bytes().get(dot_index) == Some(&b'.')
}
