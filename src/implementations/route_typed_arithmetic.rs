use std::cmp::Ordering;
use std::collections::{HashSet, hash_map::DefaultHasher};
use std::hash::BuildHasherDefault;
use std::net::Ipv6Addr;
use std::str::FromStr;

use crate::{
    EffectiveAuthority, NormalizedTarget, PolyguardError, RouteMatch, RouteRule, TargetForm,
};

const ROUTE_LIMIT: usize = 256;

struct RoutingPath<'a>(&'a str);
struct CanonicalHost<'a>(&'a str);
struct CanonicalPrefix<'a>(&'a str);
struct UpstreamName<'a>(&'a str);

struct Candidate<'a> {
    prefix: CanonicalPrefix<'a>,
    upstream: UpstreamName<'a>,
    declaration_order: usize,
}

fn invalid(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidRoute {
        reason: reason.into(),
    }
}

impl<'a> RoutingPath<'a> {
    fn from_target(target: &'a NormalizedTarget) -> Result<Self, PolyguardError> {
        match (&target.form, target.routing_path.as_bytes().first()) {
            (TargetForm::Origin | TargetForm::Absolute, Some(b'/')) => {
                Ok(Self(&target.routing_path))
            }
            (TargetForm::Origin | TargetForm::Absolute, None | Some(_))
            | (TargetForm::Authority | TargetForm::Asterisk, _) => Err(invalid("invalid_target")),
        }
    }
}

impl<'a> CanonicalHost<'a> {
    fn new(host: &'a str) -> Result<Self, PolyguardError> {
        let bytes = host.as_bytes();
        let valid = match (bytes.first(), bytes.last()) {
            (Some(b'['), Some(b']')) => {
                let address = &host[1..host.len() - 1];
                !address.is_empty()
                    && address.bytes().all(|byte| {
                        byte.is_ascii_digit()
                            || (b'a'..=b'f').contains(&byte)
                            || matches!(byte, b':' | b'.')
                    })
                    && Ipv6Addr::from_str(address).is_ok()
            }
            (Some(_), Some(_)) if bytes.len() <= 253 => host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            }),
            (None, None) | (None, Some(_)) | (Some(_), None) => false,
            (Some(_), Some(_)) => false,
        };

        match valid {
            true => Ok(Self(host)),
            false => Err(invalid("invalid_host")),
        }
    }
}

impl<'a> CanonicalPrefix<'a> {
    fn new(prefix: &'a str) -> Result<Self, PolyguardError> {
        let bytes = prefix.as_bytes();
        let shape_is_valid = match (bytes.first(), bytes.last()) {
            (Some(b'/'), Some(b'/')) => bytes.len() == 1,
            (Some(b'/'), Some(_)) => true,
            _ => false,
        };
        if !shape_is_valid {
            return Err(invalid("invalid_path_prefix"));
        }

        let mut position = 0;
        while position < bytes.len() {
            match bytes[position] {
                b'%' => match bytes.get(position + 1..position + 3) {
                    Some(hex) if hex[0].is_ascii_hexdigit() && hex[1].is_ascii_hexdigit() => {
                        if hex.iter().any(u8::is_ascii_lowercase) {
                            return Err(invalid("invalid_path_prefix"));
                        }
                        let decoded = (hex_value(hex[0]) << 4) | hex_value(hex[1]);
                        if decoded.is_ascii_alphanumeric()
                            || matches!(decoded, b'-' | b'.' | b'_' | b'~' | b'\\')
                            || decoded == 0
                            || decoded.is_ascii_control()
                        {
                            return Err(invalid("invalid_path_prefix"));
                        }
                        position += 3;
                    }
                    Some(_) | None => return Err(invalid("invalid_path_prefix")),
                },
                byte if byte.is_ascii_graphic() && !matches!(byte, b'\\' | b'?' | b'#') => {
                    position += 1;
                }
                _ => return Err(invalid("invalid_path_prefix")),
            }
        }

        if prefix
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
        {
            return Err(invalid("invalid_path_prefix"));
        }
        Ok(Self(prefix))
    }

    fn matches(&self, path: &RoutingPath<'_>) -> bool {
        match self.0 {
            "/" => true,
            prefix => match path.0.strip_prefix(prefix) {
                Some("") => true,
                Some(remainder) => remainder.as_bytes().first() == Some(&b'/'),
                None => false,
            },
        }
    }
}

impl<'a> UpstreamName<'a> {
    fn new(upstream: &'a str) -> Result<Self, PolyguardError> {
        match upstream.len() {
            1..=64
                if upstream.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
                }) =>
            {
                Ok(Self(upstream))
            }
            _ => Err(invalid("invalid_upstream")),
        }
    }
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'A'..=b'F' => byte - b'A' + 10,
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

pub fn match_route(
    authority: &EffectiveAuthority,
    target: &NormalizedTarget,
    routes: &[RouteRule],
) -> Result<RouteMatch, PolyguardError> {
    if routes.len() > ROUTE_LIMIT {
        return Err(PolyguardError::LimitExceeded {
            limit: "route_count".into(),
            max: ROUTE_LIMIT,
            actual: routes.len(),
        });
    }

    let path = RoutingPath::from_target(target)?;
    let mut orders = HashSet::with_capacity_and_hasher(
        routes.len(),
        BuildHasherDefault::<DefaultHasher>::default(),
    );
    let mut best: Option<Candidate<'_>> = None;

    for rule in routes {
        let host = CanonicalHost::new(&rule.host)?;
        let prefix = CanonicalPrefix::new(&rule.path_prefix)?;
        let upstream = UpstreamName::new(&rule.upstream)?;
        if !orders.insert(rule.declaration_order) {
            return Err(invalid("duplicate_declaration_order"));
        }

        best = match (
            host.0.eq_ignore_ascii_case(&authority.host),
            prefix.matches(&path),
        ) {
            (true, true) => {
                let challenger = Candidate {
                    prefix,
                    upstream,
                    declaration_order: rule.declaration_order,
                };
                match best {
                    None => Some(challenger),
                    Some(incumbent) => {
                        match challenger.prefix.0.len().cmp(&incumbent.prefix.0.len()) {
                            Ordering::Greater => Some(challenger),
                            Ordering::Less => Some(incumbent),
                            Ordering::Equal => {
                                match challenger
                                    .declaration_order
                                    .cmp(&incumbent.declaration_order)
                                {
                                    Ordering::Less => Some(challenger),
                                    Ordering::Equal | Ordering::Greater => Some(incumbent),
                                }
                            }
                        }
                    }
                }
            }
            (true, false) | (false, true) | (false, false) => best,
        };
    }

    match best {
        Some(candidate) => Ok(RouteMatch {
            upstream: candidate.upstream.0.into(),
            declaration_order: candidate.declaration_order,
        }),
        None => Err(PolyguardError::NoRoute),
    }
}
