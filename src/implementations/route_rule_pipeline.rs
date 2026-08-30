use std::{collections::HashSet, net::Ipv6Addr};

use crate::{
    EffectiveAuthority, NormalizedTarget, PolyguardError, Result, RouteMatch, RouteRule, TargetForm,
};

const ROUTE_LIMIT: usize = 256;
const PATH_LIMIT: usize = 8192;
const UPSTREAM_LIMIT: usize = 64;

type RuleValidator = fn(&RouteRule) -> Result<()>;

const RULE_VALIDATORS: [RuleValidator; 3] = [
    validate_rule_host,
    validate_rule_prefix,
    validate_rule_upstream,
];

#[derive(Clone, Copy)]
struct CheckedRule<'a> {
    host: &'a str,
    prefix: &'a str,
    upstream: &'a str,
    declaration_order: usize,
}

struct CheckedInput<'a> {
    authority_host: &'a str,
    routing_path: &'a [u8],
    rules: Vec<CheckedRule<'a>>,
}

/// Select a route through a validate-then-filter rule pipeline.
pub fn match_route(
    authority: &EffectiveAuthority,
    target: &NormalizedTarget,
    routes: &[RouteRule],
) -> Result<RouteMatch> {
    let checked = validate_boundary(authority, target, routes)?;

    checked
        .rules
        .iter()
        .copied()
        .filter(|rule| rule.host.eq_ignore_ascii_case(checked.authority_host))
        .filter(|rule| prefix_applies(rule.prefix.as_bytes(), checked.routing_path))
        .max_by_key(|rule| (rule.prefix.len(), std::cmp::Reverse(rule.declaration_order)))
        .map(|rule| RouteMatch {
            upstream: rule.upstream.to_owned(),
            declaration_order: rule.declaration_order,
        })
        .ok_or(PolyguardError::NoRoute)
}

fn validate_boundary<'a>(
    authority: &'a EffectiveAuthority,
    target: &'a NormalizedTarget,
    routes: &'a [RouteRule],
) -> Result<CheckedInput<'a>> {
    if routes.len() > ROUTE_LIMIT {
        return Err(PolyguardError::LimitExceeded {
            limit: "route_count".into(),
            max: ROUTE_LIMIT,
            actual: routes.len(),
        });
    }

    let routing_path = match target.form {
        TargetForm::Origin | TargetForm::Absolute
            if target.routing_path.as_bytes().first() == Some(&b'/') =>
        {
            target.routing_path.as_bytes()
        }
        TargetForm::Origin
        | TargetForm::Absolute
        | TargetForm::Authority
        | TargetForm::Asterisk => return invalid_route("invalid_target"),
    };

    let checked_rules = routes
        .iter()
        .map(check_rule)
        .collect::<Result<Vec<CheckedRule<'_>>>>()?;

    checked_rules.iter().try_fold(
        HashSet::with_capacity(checked_rules.len()),
        |mut seen, rule| {
            if seen.insert(rule.declaration_order) {
                Ok(seen)
            } else {
                invalid_route("duplicate_declaration_order")
            }
        },
    )?;

    Ok(CheckedInput {
        authority_host: &authority.host,
        routing_path,
        rules: checked_rules,
    })
}

fn check_rule(rule: &RouteRule) -> Result<CheckedRule<'_>> {
    RULE_VALIDATORS
        .iter()
        .try_for_each(|validator| validator(rule))?;

    Ok(CheckedRule {
        host: &rule.host,
        prefix: &rule.path_prefix,
        upstream: &rule.upstream,
        declaration_order: rule.declaration_order,
    })
}

fn validate_rule_host(rule: &RouteRule) -> Result<()> {
    let host = rule.host.as_str();
    if let Some(address) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return if !address.is_empty()
            && !address.contains('%')
            && !address.bytes().any(|byte| byte.is_ascii_uppercase())
            && address.parse::<Ipv6Addr>().is_ok()
        {
            Ok(())
        } else {
            invalid_route("invalid_host")
        };
    }

    let canonical_dns = (1..=253).contains(&host.len())
        && host.is_ascii()
        && !host.ends_with('.')
        && host.split('.').all(canonical_dns_label);
    canonical_dns
        .then_some(())
        .ok_or_else(|| invalid_route_value("invalid_host"))
}

fn canonical_dns_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_rule_prefix(rule: &RouteRule) -> Result<()> {
    let prefix = rule.path_prefix.as_bytes();
    let shape_is_canonical = (1..=PATH_LIMIT).contains(&prefix.len())
        && prefix.first() == Some(&b'/')
        && (prefix == b"/" || prefix.last() != Some(&b'/'));
    if !shape_is_canonical {
        return invalid_route("invalid_path_prefix");
    }

    validate_path_bytes(prefix)?;

    if prefix[1..]
        .split(|byte| *byte == b'/')
        .any(|segment| segment == b"." || segment == b"..")
    {
        return invalid_route("invalid_path_prefix");
    }
    Ok(())
}

fn validate_path_bytes(bytes: &[u8]) -> Result<()> {
    let mut cursor = 0;
    while let Some(&byte) = bytes.get(cursor) {
        cursor = match byte {
            b'%' => validate_escape(bytes, cursor)?,
            b'!'..=b'~' if !matches!(byte, b'?' | b'#' | b'\\') => cursor + 1,
            _ => return invalid_route("invalid_path_prefix"),
        };
    }
    Ok(())
}

fn validate_escape(bytes: &[u8], cursor: usize) -> Result<usize> {
    let [high, low] = bytes
        .get(cursor + 1..cursor + 3)
        .ok_or_else(|| invalid_route_value("invalid_path_prefix"))?
    else {
        return invalid_route("invalid_path_prefix");
    };
    if !is_canonical_hex(*high) || !is_canonical_hex(*low) {
        return invalid_route("invalid_path_prefix");
    }

    let decoded = hex_nibble(*high) * 16 + hex_nibble(*low);
    if matches!(decoded, 0..=31 | 127 | b'\\') || is_unreserved(decoded) {
        return invalid_route("invalid_path_prefix");
    }
    Ok(cursor + 3)
}

fn is_canonical_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("hexadecimal byte was validated"),
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn validate_rule_upstream(rule: &RouteRule) -> Result<()> {
    let valid = (1..=UPSTREAM_LIMIT).contains(&rule.upstream.len())
        && rule
            .upstream
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'));
    valid
        .then_some(())
        .ok_or_else(|| invalid_route_value("invalid_upstream"))
}

fn prefix_applies(prefix: &[u8], path: &[u8]) -> bool {
    prefix == b"/"
        || path
            .strip_prefix(prefix)
            .is_some_and(|remainder| remainder.is_empty() || remainder.first() == Some(&b'/'))
}

fn invalid_route_value(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidRoute {
        reason: reason.into(),
    }
}

fn invalid_route<T>(reason: &'static str) -> Result<T> {
    Err(invalid_route_value(reason))
}
