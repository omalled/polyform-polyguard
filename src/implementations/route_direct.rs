use std::{
    collections::{HashSet, hash_map::DefaultHasher},
    hash::BuildHasherDefault,
    net::Ipv6Addr,
};

use crate::{
    EffectiveAuthority, NormalizedTarget, PolyguardError, Result, RouteMatch, RouteRule, TargetForm,
};

const ROUTE_LIMIT: usize = 256;
const PATH_LIMIT: usize = 8192;
const UPSTREAM_LIMIT: usize = 64;

type DeclarationOrders = HashSet<usize, BuildHasherDefault<DefaultHasher>>;

#[derive(Clone, Copy)]
struct CanonicalHost<'a>(&'a str);

#[derive(Clone, Copy)]
struct CanonicalPrefix<'a>(&'a [u8]);

#[derive(Clone, Copy)]
struct UpstreamName<'a>(&'a str);

#[derive(Clone, Copy)]
struct ValidRule<'a> {
    host: CanonicalHost<'a>,
    prefix: CanonicalPrefix<'a>,
    upstream: UpstreamName<'a>,
    declaration_order: usize,
}

#[derive(Clone, Copy)]
struct Candidate<'a>(ValidRule<'a>);

/// Select a route directly from validated, borrowed rule views.
pub fn match_route(
    authority: &EffectiveAuthority,
    target: &NormalizedTarget,
    routes: &[RouteRule],
) -> Result<RouteMatch> {
    match routes.len() {
        actual if actual > ROUTE_LIMIT => {
            return Err(PolyguardError::LimitExceeded {
                limit: "route_count".into(),
                max: ROUTE_LIMIT,
                actual,
            });
        }
        _ => {}
    }

    let routing_path = match (&target.form, target.routing_path.as_bytes().first()) {
        (TargetForm::Origin | TargetForm::Absolute, Some(b'/')) => target.routing_path.as_bytes(),
        (TargetForm::Origin | TargetForm::Absolute, None | Some(_))
        | (TargetForm::Authority | TargetForm::Asterisk, _) => {
            return invalid_route("invalid_target");
        }
    };

    // The size limit is checked before this collection allocates proportionally to route count.
    let mut declaration_orders =
        DeclarationOrders::with_capacity_and_hasher(routes.len(), BuildHasherDefault::default());
    let mut winner: Option<Candidate<'_>> = None;

    for raw in routes {
        let rule = ValidRule::new(raw)?;
        match declaration_orders.insert(rule.declaration_order) {
            true => {}
            false => return invalid_route("duplicate_declaration_order"),
        }

        let host_matches = rule.host.0.eq_ignore_ascii_case(&authority.host);
        let path_matches = rule.prefix.matches(routing_path);
        match (host_matches, path_matches, winner) {
            (true, true, None) => winner = Some(Candidate(rule)),
            (true, true, Some(current)) if rule.precedes(current.0) => {
                winner = Some(Candidate(rule));
            }
            (true, true, Some(_)) | (true, false, _) | (false, true, _) | (false, false, _) => {}
        }
    }

    match winner {
        Some(Candidate(rule)) => Ok(RouteMatch {
            upstream: rule.upstream.0.to_owned(),
            declaration_order: rule.declaration_order,
        }),
        None => Err(PolyguardError::NoRoute),
    }
}

impl<'a> ValidRule<'a> {
    fn new(raw: &'a RouteRule) -> Result<Self> {
        let host = CanonicalHost::new(&raw.host)?;
        let prefix = CanonicalPrefix::new(&raw.path_prefix)?;
        let upstream = UpstreamName::new(&raw.upstream)?;
        Ok(Self {
            host,
            prefix,
            upstream,
            declaration_order: raw.declaration_order,
        })
    }

    fn precedes(self, other: Self) -> bool {
        match self.prefix.0.len().cmp(&other.prefix.0.len()) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => self.declaration_order < other.declaration_order,
            std::cmp::Ordering::Less => false,
        }
    }
}

impl<'a> CanonicalHost<'a> {
    fn new(value: &'a str) -> Result<Self> {
        match value.strip_prefix('[') {
            Some(after_open) => match after_open.strip_suffix(']') {
                Some(address)
                    if !address.is_empty()
                        && !address.contains('%')
                        && !address.bytes().any(|byte| byte.is_ascii_uppercase())
                        && address.parse::<Ipv6Addr>().is_ok() =>
                {
                    Ok(Self(value))
                }
                Some(_) | None => invalid_route("invalid_host"),
            },
            None => match canonical_dns(value) {
                true => Ok(Self(value)),
                false => invalid_route("invalid_host"),
            },
        }
    }
}

impl<'a> CanonicalPrefix<'a> {
    fn new(value: &'a str) -> Result<Self> {
        let bytes = value.as_bytes();
        match (bytes.len(), bytes.first(), bytes.last()) {
            (0, _, _) | (_, None, _) | (_, Some(_), Some(b'/')) if value != "/" => {
                return invalid_route("invalid_path_prefix");
            }
            (length, _, _) if length > PATH_LIMIT => {
                return invalid_route("invalid_path_prefix");
            }
            (_, Some(b'/'), _) => {}
            _ => return invalid_route("invalid_path_prefix"),
        }

        let mut offset = 0;
        while offset < bytes.len() {
            match bytes[offset] {
                b'%' => match canonical_escape(bytes, offset) {
                    Some(next) => offset = next,
                    None => return invalid_route("invalid_path_prefix"),
                },
                b'?' | b'#' | b'\\' | 0..=32 | 127..=u8::MAX => {
                    return invalid_route("invalid_path_prefix");
                }
                _ => offset += 1,
            }
        }

        match bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|segment| matches!(segment, b"." | b".."))
        {
            true => invalid_route("invalid_path_prefix"),
            false => Ok(Self(bytes)),
        }
    }

    fn matches(self, path: &[u8]) -> bool {
        match self.0 {
            b"/" => true,
            prefix => match path.strip_prefix(prefix) {
                Some([]) => true,
                Some([b'/', ..]) => true,
                Some(_) | None => false,
            },
        }
    }
}

impl<'a> UpstreamName<'a> {
    fn new(value: &'a str) -> Result<Self> {
        match value.len() {
            1..=UPSTREAM_LIMIT
                if value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
                }) =>
            {
                Ok(Self(value))
            }
            _ => invalid_route("invalid_upstream"),
        }
    }
}

fn canonical_dns(value: &str) -> bool {
    match value.len() {
        1..=253 if value.is_ascii() && !value.ends_with('.') => {
            value.split('.').all(|label| match label.as_bytes() {
                [] => false,
                bytes if bytes.len() > 63 => false,
                [b'-', ..] | [.., b'-'] => false,
                bytes => bytes.iter().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'
                }),
            })
        }
        _ => false,
    }
}

fn canonical_escape(bytes: &[u8], offset: usize) -> Option<usize> {
    match (bytes.get(offset + 1), bytes.get(offset + 2)) {
        (Some(high), Some(low)) if is_upper_hex(*high) && is_upper_hex(*low) => {
            let decoded = (hex_value(*high) << 4) | hex_value(*low);
            match decoded {
                0..=31 | 127 | b'\\' => None,
                byte if byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~') =>
                {
                    None
                }
                _ => Some(offset + 3),
            }
        }
        _ => None,
    }
}

fn is_upper_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn invalid_route<T>(reason: &'static str) -> Result<T> {
    Err(PolyguardError::InvalidRoute {
        reason: reason.into(),
    })
}
