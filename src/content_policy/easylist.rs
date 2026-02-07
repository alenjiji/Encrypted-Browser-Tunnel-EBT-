use super::{ReasonCode, Rule, RuleAction, RuleSet};

const EASYLIST_MAX_RULES: usize = 50_000;
const EASYLIST_MAX_LINE_LEN: usize = 1024;

pub fn ruleset_from_easylist(text: &str) -> RuleSet {
    let mut rules = Vec::new();

    for raw_line in text.lines() {
        if rules.len() >= EASYLIST_MAX_RULES {
            break;
        }

        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > EASYLIST_MAX_LINE_LEN {
            continue;
        }
        if is_comment_or_header(line) {
            continue;
        }
        if is_cosmetic_or_element_hiding(line) {
            continue;
        }
        if line.contains('$') {
            continue;
        }
        if is_regex_rule(line) {
            continue;
        }

        if let Some(rule) = parse_domain_rule(line) {
            rules.push(rule);
        }
    }

    RuleSet::new(rules)
}

fn parse_domain_rule(line: &str) -> Option<Rule> {
    let (action, body) = parse_action(line)?;

    if let Some(suffix) = parse_domain_suffix(body) {
        return Some(Rule::DomainSuffix { suffix, action });
    }

    if let Some(domain) = parse_domain_exact(body) {
        return Some(Rule::DomainExact { domain, action });
    }

    None
}

fn parse_action(line: &str) -> Option<(RuleAction, &str)> {
    if let Some(body) = line.strip_prefix("@@") {
        Some((RuleAction::Allow, body))
    } else {
        Some((RuleAction::Block(ReasonCode::Ads), line))
    }
}

fn parse_domain_suffix(body: &str) -> Option<String> {
    let target = body.strip_prefix("||")?;
    let (domain, rest) = split_domain_target(target)?;

    if rest.is_empty() || rest == "^" {
        Some(domain.to_string())
    } else {
        None
    }
}

fn parse_domain_exact(body: &str) -> Option<String> {
    if let Some(url) = body.strip_prefix("|http://") {
        return parse_exact_from_url(url);
    }
    if let Some(url) = body.strip_prefix("|https://") {
        return parse_exact_from_url(url);
    }

    if is_simple_domain(body) {
        return Some(body.to_string());
    }

    None
}

fn parse_exact_from_url(url: &str) -> Option<String> {
    let (domain, rest) = split_domain_target(url)?;

    if rest.is_empty() || rest == "^" || rest == "/" {
        Some(domain.to_string())
    } else {
        None
    }
}

fn split_domain_target(target: &str) -> Option<(&str, &str)> {
    if target.is_empty() {
        return None;
    }
    let mut end = 0;
    for (idx, ch) in target.char_indices() {
        if is_domain_char(ch) {
            end = idx + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    let domain = &target[..end];
    let rest = &target[end..];

    if !is_simple_domain(domain) {
        return None;
    }

    if rest.starts_with(':') {
        return None;
    }

    Some((domain, rest))
}

fn is_comment_or_header(line: &str) -> bool {
    line.starts_with('!') || line.starts_with('[')
}

fn is_cosmetic_or_element_hiding(line: &str) -> bool {
    line.contains("##")
        || line.contains("#@#")
        || line.contains("#?#")
        || line.contains("#@?")
        || line.contains("#$#")
        || line.contains("#@$#")
}

fn is_regex_rule(line: &str) -> bool {
    line.starts_with('/') && line.ends_with('/') && line.len() > 1
}

fn is_domain_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '-' || ch == '.'
}

fn is_simple_domain(domain: &str) -> bool {
    if domain.is_empty() {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    let mut prev_dot = false;
    for ch in domain.chars() {
        if !is_domain_char(ch) {
            return false;
        }
        if ch == '.' {
            if prev_dot {
                return false;
            }
            prev_dot = true;
        } else {
            prev_dot = false;
        }
    }
    true
}
