use std::{cmp::Ordering, net::Ipv6Addr};

use crate::{
    EffectiveAuthority, NormalizedTarget, PolyguardError, Result, RouteMatch, RouteRule, TargetForm,
};

const MAX_ROUTES: usize = 256;
const MAX_PREFIX_BYTES: usize = 8192;
const MAX_UPSTREAM_BYTES: usize = 64;

#[derive(Clone, Copy)]
struct RoutingPath<'a>(&'a [u8]);

#[derive(Clone, Copy)]
enum HostName<'a> {
    Dns(&'a str),
    Ipv6(&'a str),
}

#[derive(Clone, Copy)]
struct PathPrefix<'a>(&'a [u8]);

#[derive(Clone, Copy)]
struct Upstream<'a>(&'a str);

#[derive(Clone, Copy)]
struct Rank {
    prefix_bytes: usize,
    declaration_order: usize,
}

#[derive(Clone, Copy)]
struct Winner<'a> {
    rank: Rank,
    upstream: Upstream<'a>,
}

enum Eligibility {
    Eligible,
    HostMismatch,
    PathMismatch,
    BothMismatch,
}

struct DeclarationOrders {
    values: [usize; MAX_ROUTES],
    occupied: [u64; MAX_ROUTES / u64::BITS as usize],
}

impl DeclarationOrders {
    fn empty() -> Self {
        Self {
            values: [0; MAX_ROUTES],
            occupied: [0; MAX_ROUTES / u64::BITS as usize],
        }
    }

    fn insert(&mut self, value: usize) -> bool {
        let mut slot = value.wrapping_mul(0x9e37_79b9_usize) & (MAX_ROUTES - 1);

        for _ in 0..MAX_ROUTES {
            let word = slot / u64::BITS as usize;
            let mask = 1_u64 << (slot % u64::BITS as usize);
            match (self.occupied[word] & mask != 0, self.values[slot] == value) {
                (false, _) => {
                    self.values[slot] = value;
                    self.occupied[word] |= mask;
                    return true;
                }
                (true, true) => return false,
                (true, false) => slot = (slot + 1) & (MAX_ROUTES - 1),
            }
        }

        // A full table means all 256 bounded declarations were distinct.
        true
    }
}

/// Select an upstream with bounded borrowed domain values and an explicit rank comparison.
pub fn match_route(
    authority: &EffectiveAuthority,
    target: &NormalizedTarget,
    routes: &[RouteRule],
) -> Result<RouteMatch> {
    match routes.len() {
        actual if actual > MAX_ROUTES => {
            return Err(PolyguardError::LimitExceeded {
                limit: "route_count".into(),
                max: MAX_ROUTES,
                actual,
            });
        }
        _ => {}
    }

    let routing_path = RoutingPath::from_target(target)?;
    let mut orders = DeclarationOrders::empty();
    let mut winner = None;

    for rule in routes {
        let host = HostName::parse(&rule.host)?;
        let prefix = PathPrefix::parse(&rule.path_prefix)?;
        let upstream = Upstream::parse(&rule.upstream)?;

        match orders.insert(rule.declaration_order) {
            true => {}
            false => return invalid_route("duplicate_declaration_order"),
        }

        let eligibility = match (host.matches(&authority.host), prefix.matches(routing_path)) {
            (true, true) => Eligibility::Eligible,
            (false, true) => Eligibility::HostMismatch,
            (true, false) => Eligibility::PathMismatch,
            (false, false) => Eligibility::BothMismatch,
        };

        match eligibility {
            Eligibility::Eligible => {
                let challenger = Winner {
                    rank: Rank {
                        prefix_bytes: prefix.0.len(),
                        declaration_order: rule.declaration_order,
                    },
                    upstream,
                };
                winner = choose(winner, challenger);
            }
            Eligibility::HostMismatch | Eligibility::PathMismatch | Eligibility::BothMismatch => {}
        }
    }

    match winner {
        Some(selected) => Ok(RouteMatch {
            upstream: selected.upstream.0.to_owned(),
            declaration_order: selected.rank.declaration_order,
        }),
        None => Err(PolyguardError::NoRoute),
    }
}

fn choose<'a>(current: Option<Winner<'a>>, challenger: Winner<'a>) -> Option<Winner<'a>> {
    match current {
        None => Some(challenger),
        Some(selected) => match challenger
            .rank
            .prefix_bytes
            .cmp(&selected.rank.prefix_bytes)
        {
            Ordering::Greater => Some(challenger),
            Ordering::Less => Some(selected),
            Ordering::Equal => match challenger
                .rank
                .declaration_order
                .cmp(&selected.rank.declaration_order)
            {
                Ordering::Less => Some(challenger),
                Ordering::Equal | Ordering::Greater => Some(selected),
            },
        },
    }
}

impl<'a> RoutingPath<'a> {
    fn from_target(target: &'a NormalizedTarget) -> Result<Self> {
        match (&target.form, target.routing_path.as_bytes()) {
            (TargetForm::Origin, bytes @ [b'/', ..])
            | (TargetForm::Absolute, bytes @ [b'/', ..]) => Ok(Self(bytes)),
            (TargetForm::Origin, [])
            | (TargetForm::Origin, [_, ..])
            | (TargetForm::Absolute, [])
            | (TargetForm::Absolute, [_, ..])
            | (TargetForm::Authority, _)
            | (TargetForm::Asterisk, _) => invalid_route("invalid_target"),
        }
    }
}

impl<'a> HostName<'a> {
    fn parse(text: &'a str) -> Result<Self> {
        match (text.strip_prefix('['), text.strip_suffix(']')) {
            (Some(after_open), Some(_)) => {
                let literal = &after_open[..after_open.len() - 1];
                match (
                    literal.is_empty(),
                    literal.contains('%'),
                    literal.bytes().any(|byte| byte.is_ascii_uppercase()),
                    literal.parse::<Ipv6Addr>(),
                ) {
                    (false, false, false, Ok(_)) => Ok(Self::Ipv6(text)),
                    (true, _, _, _) | (_, true, _, _) | (_, _, true, _) | (_, _, _, Err(_)) => {
                        invalid_route("invalid_host")
                    }
                }
            }
            (Some(_), None) | (None, Some(_)) => invalid_route("invalid_host"),
            (None, None) => validate_dns(text).map(|()| Self::Dns(text)),
        }
    }

    fn matches(self, authority: &str) -> bool {
        match self {
            Self::Dns(text) | Self::Ipv6(text) => text.eq_ignore_ascii_case(authority),
        }
    }
}

fn validate_dns(text: &str) -> Result<()> {
    match (text.len(), text.is_ascii(), text.ends_with('.')) {
        (1..=253, true, false) => {}
        (0, _, _) | (254.., _, _) | (_, false, _) | (_, _, true) => {
            return invalid_route("invalid_host");
        }
    }

    for label in text.as_bytes().split(|byte| *byte == b'.') {
        match label {
            [] | [b'-', ..] | [.., b'-'] => return invalid_route("invalid_host"),
            bytes if bytes.len() > 63 => return invalid_route("invalid_host"),
            bytes => {
                for byte in bytes {
                    match byte {
                        b'a'..=b'z' | b'0'..=b'9' | b'-' => {}
                        _ => return invalid_route("invalid_host"),
                    }
                }
            }
        }
    }
    Ok(())
}

impl<'a> PathPrefix<'a> {
    fn parse(text: &'a str) -> Result<Self> {
        let bytes = text.as_bytes();
        match bytes {
            [] => return invalid_route("invalid_path_prefix"),
            [b'/', ..] if bytes.len() > MAX_PREFIX_BYTES => {
                return invalid_route("invalid_path_prefix");
            }
            [b'/'] => {}
            [b'/', .., b'/'] => return invalid_route("invalid_path_prefix"),
            [b'/', ..] => {}
            [_first, ..] => return invalid_route("invalid_path_prefix"),
        }

        let mut cursor = 0;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'%' => cursor = canonical_escape_end(bytes, cursor)?,
                b'!'..=b'~' if !matches!(bytes[cursor], b'?' | b'#' | b'\\') => cursor += 1,
                _ => return invalid_route("invalid_path_prefix"),
            }
        }

        for segment in bytes[1..].split(|byte| *byte == b'/') {
            match segment {
                b"." | b".." => return invalid_route("invalid_path_prefix"),
                _ => {}
            }
        }

        Ok(Self(bytes))
    }

    fn matches(self, path: RoutingPath<'_>) -> bool {
        match self.0 {
            b"/" => true,
            prefix => match path.0.get(..prefix.len()) {
                Some(beginning) if beginning == prefix => match path.0.get(prefix.len()) {
                    None | Some(b'/') => true,
                    Some(_) => false,
                },
                Some(_) | None => false,
            },
        }
    }
}

fn canonical_escape_end(bytes: &[u8], percent: usize) -> Result<usize> {
    match (bytes.get(percent + 1), bytes.get(percent + 2)) {
        (Some(high @ (b'0'..=b'9' | b'A'..=b'F')), Some(low @ (b'0'..=b'9' | b'A'..=b'F'))) => {
            let decoded = (hex(*high) << 4) | hex(*low);
            match decoded {
                0..=31 | 127 | b'\\' => invalid_route("invalid_path_prefix"),
                byte if byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~') =>
                {
                    invalid_route("invalid_path_prefix")
                }
                _ => Ok(percent + 3),
            }
        }
        (None, _) | (_, None) | (Some(_), Some(_)) => invalid_route("invalid_path_prefix"),
    }
}

fn hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("escape byte is exhaustively validated"),
    }
}

impl<'a> Upstream<'a> {
    fn parse(text: &'a str) -> Result<Self> {
        match text.len() {
            1..=MAX_UPSTREAM_BYTES => {}
            _ => return invalid_route("invalid_upstream"),
        }
        for byte in text.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' => {}
                _ => return invalid_route("invalid_upstream"),
            }
        }
        Ok(Self(text))
    }
}

fn invalid_route<T>(reason: &'static str) -> Result<T> {
    Err(PolyguardError::InvalidRoute {
        reason: reason.into(),
    })
}
