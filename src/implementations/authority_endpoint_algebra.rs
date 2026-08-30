use std::net::Ipv6Addr;

use crate::{
    EffectiveAuthority, HeaderBlock, NormalizedTarget, PolyguardError, Result, TargetForm,
};

#[derive(Clone, Copy)]
struct SchemeDefault(Option<u16>);

#[derive(Clone, Copy)]
enum RawHost<'a> {
    Dns(&'a str),
    Ipv6(&'a str),
}

#[derive(Clone, Copy)]
struct ValidatedAuthority<'a> {
    host: RawHost<'a>,
    port: Option<u16>,
}

#[derive(PartialEq, Eq)]
struct CanonicalHost(String);

struct CanonicalAuthority {
    host: CanonicalHost,
    explicit_port: Option<u16>,
}

enum HostField<T> {
    Missing,
    Present(T),
}

struct CanonicalEvidence<'a> {
    form: &'a TargetForm,
    scheme: Option<&'a str>,
    target: Option<CanonicalAuthority>,
    header: HostField<CanonicalAuthority>,
}

/// Reconcile authorities by validating raw, type-directed values first and
/// then comparing the algebraic endpoint `(canonical host, effective port)`.
pub fn reconcile_authority(
    target: &NormalizedTarget,
    headers: &HeaderBlock,
) -> Result<EffectiveAuthority> {
    // Collect and validate every supplied spelling before applying any form,
    // source-preference, agreement, or default-port transformation.
    let header = observe_host(headers)?;
    let target_authority = target
        .authority
        .as_deref()
        .map(validate_authority)
        .transpose()?;

    let evidence = CanonicalEvidence {
        form: &target.form,
        scheme: target.scheme.as_deref(),
        target: target_authority.map(canonicalize),
        header: match header {
            HostField::Missing => HostField::Missing,
            HostField::Present(value) => HostField::Present(canonicalize(value)),
        },
    };
    decision_table(evidence)
}

fn observe_host(headers: &HeaderBlock) -> Result<HostField<ValidatedAuthority<'_>>> {
    let mut observed = None;
    for field in &headers.fields {
        if field.name != "host" {
            continue;
        }
        if observed.replace(field.value.as_slice()).is_some() {
            return Err(PolyguardError::MultipleHost);
        }
    }

    let Some(value) = observed else {
        return Ok(HostField::Missing);
    };
    if value.contains(&b',') {
        return Err(comma_value_error(value));
    }
    let text = std::str::from_utf8(value).map_err(|_| PolyguardError::InvalidAuthority)?;
    Ok(HostField::Present(validate_authority(text)?))
}

fn comma_value_error(value: &[u8]) -> PolyguardError {
    let mut pieces = value.split(|byte| *byte == b',');
    let first = pieces.next().unwrap_or_default();
    if !first.is_empty() && pieces.all(|piece| piece == first) {
        PolyguardError::MultipleHost
    } else {
        PolyguardError::InvalidAuthority
    }
}

fn decision_table(evidence: CanonicalEvidence<'_>) -> Result<EffectiveAuthority> {
    // The complete public-input shape policy lives in this one table.
    match (
        evidence.form,
        evidence.scheme,
        evidence.target,
        evidence.header,
    ) {
        (TargetForm::Origin | TargetForm::Asterisk, None, None, HostField::Present(header)) => {
            Ok(as_effective(header, SchemeDefault(None)))
        }
        (TargetForm::Origin | TargetForm::Asterisk, None, None, HostField::Missing) => {
            Err(PolyguardError::MissingHost)
        }
        (TargetForm::Absolute, Some("http"), Some(target), header) => {
            derive_effective(target, header, SchemeDefault(Some(80)))
        }
        (TargetForm::Absolute, Some("https"), Some(target), header) => {
            derive_effective(target, header, SchemeDefault(Some(443)))
        }
        (TargetForm::Authority, None, Some(target), header) => {
            derive_effective(target, header, SchemeDefault(None))
        }
        _ => Err(PolyguardError::InvalidAuthority),
    }
}

fn derive_effective(
    preferred: CanonicalAuthority,
    corroborating: HostField<CanonicalAuthority>,
    default: SchemeDefault,
) -> Result<EffectiveAuthority> {
    if let HostField::Present(header) = corroborating
        && endpoint_key(&preferred, default) != endpoint_key(&header, default)
    {
        return Err(PolyguardError::AuthorityMismatch);
    }
    Ok(as_effective(preferred, default))
}

fn validate_authority(input: &str) -> Result<ValidatedAuthority<'_>> {
    if input.is_empty()
        || !input.is_ascii()
        || input.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b',' | b'@' | b'/' | b'\\' | b'?' | b'#' | b'%')
        })
    {
        return Err(PolyguardError::InvalidAuthority);
    }

    if let Some(after_open) = input.strip_prefix('[') {
        validate_ipv6_authority(after_open)
    } else {
        validate_dns_authority(input)
    }
}

fn validate_ipv6_authority(after_open: &str) -> Result<ValidatedAuthority<'_>> {
    let close = after_open
        .find(']')
        .ok_or(PolyguardError::InvalidAuthority)?;
    let address = &after_open[..close];
    address
        .parse::<Ipv6Addr>()
        .map_err(|_| PolyguardError::InvalidAuthority)?;

    let suffix = &after_open[close + 1..];
    let port = match suffix {
        "" => None,
        _ => Some(parse_port(
            suffix
                .strip_prefix(':')
                .ok_or(PolyguardError::InvalidAuthority)?,
        )?),
    };
    Ok(ValidatedAuthority {
        host: RawHost::Ipv6(address),
        port,
    })
}

fn validate_dns_authority(input: &str) -> Result<ValidatedAuthority<'_>> {
    let colon_count = input.bytes().filter(|byte| *byte == b':').count();
    let (spelled_host, port) = match colon_count {
        0 => (input, None),
        1 => {
            let (host, digits) = input
                .split_once(':')
                .ok_or(PolyguardError::InvalidAuthority)?;
            (host, Some(parse_port(digits)?))
        }
        _ => return Err(PolyguardError::InvalidAuthority),
    };

    let host = spelled_host.strip_suffix('.').unwrap_or(spelled_host);
    if host.is_empty() || host.len() > 253 {
        return Err(PolyguardError::InvalidAuthority);
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.as_bytes().first() == Some(&b'-')
            || label.as_bytes().last() == Some(&b'-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(PolyguardError::InvalidAuthority);
    }

    Ok(ValidatedAuthority {
        host: RawHost::Dns(host),
        port,
    })
}

fn parse_port(digits: &str) -> Result<u16> {
    let port = digits.bytes().try_fold(0_u32, |value, digit| {
        if !digit.is_ascii_digit() {
            return None;
        }
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(digit - b'0')))
    });
    match port {
        Some(value @ 1..=65_535) if !digits.is_empty() => Ok(value as u16),
        _ => Err(PolyguardError::InvalidAuthority),
    }
}

fn canonicalize(authority: ValidatedAuthority<'_>) -> CanonicalAuthority {
    let host = match authority.host {
        RawHost::Dns(name) => name.to_ascii_lowercase(),
        RawHost::Ipv6(address) => {
            let mut rendered = String::with_capacity(address.len() + 2);
            rendered.push('[');
            rendered.push_str(&address.to_ascii_lowercase());
            rendered.push(']');
            rendered
        }
    };
    CanonicalAuthority {
        host: CanonicalHost(host),
        explicit_port: authority.port,
    }
}

fn endpoint_key(
    authority: &CanonicalAuthority,
    default: SchemeDefault,
) -> (&CanonicalHost, Option<u16>) {
    (&authority.host, authority.explicit_port.or(default.0))
}

fn as_effective(authority: CanonicalAuthority, default: SchemeDefault) -> EffectiveAuthority {
    EffectiveAuthority {
        host: authority.host.0,
        port: authority
            .explicit_port
            .filter(|explicit| Some(*explicit) != default.0),
    }
}
