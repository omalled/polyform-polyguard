use std::net::Ipv6Addr;

use crate::{
    EffectiveAuthority, HeaderBlock, NormalizedTarget, PolyguardError, Result, TargetForm,
};

#[derive(Clone, Copy)]
struct DefaultPort(Option<u16>);

#[derive(Clone, Copy)]
enum ValidHost<'a> {
    Dns(&'a str),
    Ipv6(&'a str),
}

#[derive(Clone, Copy)]
struct ValidAuthority<'a> {
    host: ValidHost<'a>,
    explicit_port: Option<u16>,
}

enum HostInput<'a> {
    Absent,
    One(&'a str),
}

struct ReconciliationInputs<'target, 'header> {
    target: Option<&'target str>,
    header: Option<&'header str>,
    default_port: DefaultPort,
}

/// Derive the effective authority from a form/cardinality decision table and
/// equality invariants over validated wrapper values.
pub fn reconcile_authority(
    target: &NormalizedTarget,
    headers: &HeaderBlock,
) -> Result<EffectiveAuthority> {
    let host = inspect_host_fields(headers)?;
    let inputs = decide_inputs(target, host)?;

    // Both sources become validated values before comparison or rendering.
    let target_authority = inputs.target.map(ValidAuthority::parse).transpose()?;
    let header_authority = inputs.header.map(ValidAuthority::parse).transpose()?;

    if let (Some(target), Some(header)) = (target_authority, header_authority)
        && !target.same_endpoint(header, inputs.default_port)
    {
        return Err(PolyguardError::AuthorityMismatch);
    }

    target_authority
        .or(header_authority)
        .map(|authority| authority.into_effective(inputs.default_port))
        .ok_or(PolyguardError::MissingHost)
}

fn inspect_host_fields(headers: &HeaderBlock) -> Result<HostInput<'_>> {
    let mut value = None;
    for field in &headers.fields {
        if field.name == "host" {
            if value.is_some() {
                return Err(PolyguardError::MultipleHost);
            }
            value = Some(field.value.as_slice());
        }
    }

    let Some(bytes) = value else {
        return Ok(HostInput::Absent);
    };

    if bytes.contains(&b',') {
        let mut members = bytes.split(|byte| *byte == b',');
        let first = members.next().unwrap_or_default();
        return if !first.is_empty() && members.all(|member| member == first) {
            Err(PolyguardError::MultipleHost)
        } else {
            Err(PolyguardError::InvalidAuthority)
        };
    }

    std::str::from_utf8(bytes)
        .map(HostInput::One)
        .map_err(|_| PolyguardError::InvalidAuthority)
}

fn decide_inputs<'target, 'header>(
    target: &'target NormalizedTarget,
    host: HostInput<'header>,
) -> Result<ReconciliationInputs<'target, 'header>> {
    let header = match host {
        HostInput::Absent => None,
        HostInput::One(value) => Some(value),
    };

    // This table is the only place where target shape, Host cardinality, and
    // scheme defaults influence control flow.
    match (
        &target.form,
        target.scheme.as_deref(),
        target.authority.as_deref(),
        header,
    ) {
        (TargetForm::Origin | TargetForm::Asterisk, None, None, Some(header)) => {
            Ok(ReconciliationInputs {
                target: None,
                header: Some(header),
                default_port: DefaultPort(None),
            })
        }
        (TargetForm::Origin | TargetForm::Asterisk, None, None, None) => {
            Err(PolyguardError::MissingHost)
        }
        (TargetForm::Absolute, Some("http"), Some(authority), header) => Ok(ReconciliationInputs {
            target: Some(authority),
            header,
            default_port: DefaultPort(Some(80)),
        }),
        (TargetForm::Absolute, Some("https"), Some(authority), header) => {
            Ok(ReconciliationInputs {
                target: Some(authority),
                header,
                default_port: DefaultPort(Some(443)),
            })
        }
        (TargetForm::Authority, None, Some(authority), header) => Ok(ReconciliationInputs {
            target: Some(authority),
            header,
            default_port: DefaultPort(None),
        }),
        _ => Err(PolyguardError::InvalidAuthority),
    }
}

impl<'a> ValidAuthority<'a> {
    fn parse(input: &'a str) -> Result<Self> {
        reject_forbidden_authority_bytes(input)?;

        if input.starts_with('[') {
            Self::parse_ipv6(input)
        } else {
            Self::parse_dns(input)
        }
    }

    fn parse_ipv6(input: &'a str) -> Result<Self> {
        let closing = input.find(']').ok_or(PolyguardError::InvalidAuthority)?;
        let address = &input[1..closing];
        if address.is_empty() || address.parse::<Ipv6Addr>().is_err() {
            return Err(PolyguardError::InvalidAuthority);
        }

        let suffix = &input[closing + 1..];
        let explicit_port = match suffix {
            "" => None,
            value => Some(parse_port(
                value
                    .strip_prefix(':')
                    .ok_or(PolyguardError::InvalidAuthority)?,
            )?),
        };

        Ok(Self {
            host: ValidHost::Ipv6(&input[..=closing]),
            explicit_port,
        })
    }

    fn parse_dns(input: &'a str) -> Result<Self> {
        let (name, explicit_port) = match input.split_once(':') {
            None => (input, None),
            Some((name, port)) if !port.contains(':') => (name, Some(parse_port(port)?)),
            Some(_) => return Err(PolyguardError::InvalidAuthority),
        };
        let name = name.strip_suffix('.').unwrap_or(name);

        if name.is_empty() || name.len() > 253 {
            return Err(PolyguardError::InvalidAuthority);
        }
        if name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }) {
            return Err(PolyguardError::InvalidAuthority);
        }

        Ok(Self {
            host: ValidHost::Dns(name),
            explicit_port,
        })
    }

    fn same_endpoint(self, other: Self, default: DefaultPort) -> bool {
        self.host.same_canonical_host(other.host)
            && self.explicit_port.or(default.0) == other.explicit_port.or(default.0)
    }

    fn into_effective(self, default: DefaultPort) -> EffectiveAuthority {
        EffectiveAuthority {
            host: self.host.as_str().to_ascii_lowercase(),
            port: self.explicit_port.filter(|port| Some(*port) != default.0),
        }
    }
}

impl<'a> ValidHost<'a> {
    fn as_str(self) -> &'a str {
        match self {
            Self::Dns(value) | Self::Ipv6(value) => value,
        }
    }

    fn same_canonical_host(self, other: Self) -> bool {
        match (self, other) {
            (Self::Dns(left), Self::Dns(right)) | (Self::Ipv6(left), Self::Ipv6(right)) => {
                left.eq_ignore_ascii_case(right)
            }
            _ => false,
        }
    }
}

fn reject_forbidden_authority_bytes(input: &str) -> Result<()> {
    if input.is_empty()
        || !input.is_ascii()
        || input.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_control()
                || matches!(byte, b',' | b'@' | b'/' | b'?' | b'#' | b'%')
        })
    {
        Err(PolyguardError::InvalidAuthority)
    } else {
        Ok(())
    }
}

fn parse_port(input: &str) -> Result<u16> {
    let mut value = 0_u32;
    if input.is_empty() {
        return Err(PolyguardError::InvalidAuthority);
    }
    for digit in input.bytes() {
        if !digit.is_ascii_digit() {
            return Err(PolyguardError::InvalidAuthority);
        }
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(digit - b'0')))
            .ok_or(PolyguardError::InvalidAuthority)?;
        if value > u32::from(u16::MAX) {
            return Err(PolyguardError::InvalidAuthority);
        }
    }

    u16::try_from(value)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(PolyguardError::InvalidAuthority)
}
