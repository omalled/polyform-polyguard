use std::cmp::Reverse;
use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::BuildHasherDefault;
use std::net::Ipv6Addr;

use crate::{
    EffectiveAuthority, NormalizedTarget, PolyguardError, Result, RouteMatch, RouteRule, TargetForm,
};

const ROUTE_LIMIT: usize = 256;
type OrderSet = HashSet<usize, BuildHasherDefault<DefaultHasher>>;

#[derive(Clone, Copy)]
struct RuleRequirement {
    reason: &'static str,
    accepts: fn(&RouteRule) -> bool,
}

const RULE_REQUIREMENTS: [RuleRequirement; 3] = [
    RuleRequirement {
        reason: "invalid_host",
        accepts: |rule| canonical_host(&rule.host),
    },
    RuleRequirement {
        reason: "invalid_path_prefix",
        accepts: |rule| canonical_prefix(&rule.path_prefix),
    },
    RuleRequirement {
        reason: "invalid_upstream",
        accepts: |rule| canonical_upstream(&rule.upstream),
    },
];

#[derive(Clone, Copy)]
struct ValidRule<'a> {
    host: &'a str,
    prefix: &'a str,
    upstream: &'a str,
    order: usize,
}

pub fn match_route(
    authority: &EffectiveAuthority,
    target: &NormalizedTarget,
    routes: &[RouteRule],
) -> Result<RouteMatch> {
    if routes.len() > ROUTE_LIMIT {
        return Err(PolyguardError::LimitExceeded {
            limit: "route_count".into(),
            max: ROUTE_LIMIT,
            actual: routes.len(),
        });
    }

    let routing_path = match target.form {
        TargetForm::Origin | TargetForm::Absolute if target.routing_path.starts_with('/') => {
            target.routing_path.as_str()
        }
        _ => return Err(invalid_route("invalid_target")),
    };

    let mut seen_orders = OrderSet::with_capacity_and_hasher(
        routes.len(),
        BuildHasherDefault::<DefaultHasher>::default(),
    );
    let valid_rules = routes
        .iter()
        .map(|rule| validate_rule(rule, &mut seen_orders))
        .collect::<Result<Vec<_>>>()?;

    valid_rules
        .into_iter()
        .filter(|rule| rule.host.eq_ignore_ascii_case(&authority.host))
        .filter(|rule| prefix_covers(rule.prefix, routing_path))
        .max_by_key(|rule| (rule.prefix.len(), Reverse(rule.order)))
        .map(|rule| RouteMatch {
            upstream: rule.upstream.to_owned(),
            declaration_order: rule.order,
        })
        .ok_or(PolyguardError::NoRoute)
}

fn validate_rule<'a>(rule: &'a RouteRule, seen_orders: &mut OrderSet) -> Result<ValidRule<'a>> {
    if let Some(failed) = RULE_REQUIREMENTS
        .iter()
        .find(|requirement| !(requirement.accepts)(rule))
    {
        return Err(invalid_route(failed.reason));
    }
    if !seen_orders.insert(rule.declaration_order) {
        return Err(invalid_route("duplicate_declaration_order"));
    }

    Ok(ValidRule {
        host: &rule.host,
        prefix: &rule.path_prefix,
        upstream: &rule.upstream,
        order: rule.declaration_order,
    })
}

fn canonical_host(host: &str) -> bool {
    if let Some(interior) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        return !interior.is_empty()
            && interior.bytes().all(|byte| !byte.is_ascii_uppercase())
            && interior.parse::<Ipv6Addr>().is_ok();
    }

    !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|byte| !byte.is_ascii_uppercase())
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn canonical_prefix(prefix: &str) -> bool {
    if !prefix.starts_with('/') || (prefix.len() > 1 && prefix.ends_with('/')) {
        return false;
    }

    let bytes = prefix.as_bytes();
    let mut position = 0;
    while position < bytes.len() {
        let byte = bytes[position];
        if byte == b'%' {
            let Some(encoded) = bytes
                .get(position + 1..position + 3)
                .and_then(decode_upper_hex)
            else {
                return false;
            };
            if is_unreserved(encoded) || encoded == b'\\' || encoded <= 0x1f || encoded == 0x7f {
                return false;
            }
            position += 3;
            continue;
        }
        if !byte.is_ascii() || byte <= 0x20 || byte == 0x7f || matches!(byte, b'\\' | b'?' | b'#') {
            return false;
        }
        position += 1;
    }

    !prefix
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
}

fn decode_upper_hex(pair: &[u8]) -> Option<u8> {
    let digit = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    Some(digit(pair[0])? * 16 + digit(pair[1])?)
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn canonical_upstream(upstream: &str) -> bool {
    (1..=64).contains(&upstream.len())
        && upstream
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn prefix_covers(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || path
            .strip_prefix(prefix)
            .is_some_and(|remainder| remainder.is_empty() || remainder.starts_with('/'))
}

fn invalid_route(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidRoute {
        reason: reason.into(),
    }
}
