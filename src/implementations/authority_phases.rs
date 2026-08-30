use std::net::Ipv6Addr;

use crate::{
    EffectiveAuthority, HeaderBlock, NormalizedTarget, PolyguardError, Result, TargetForm,
};

#[derive(Debug, PartialEq, Eq)]
struct Authority {
    host: String,
    port: Option<u16>,
}

#[derive(Clone, Copy)]
enum DefaultPort {
    None,
    Http,
    Https,
}

impl DefaultPort {
    fn number(self) -> Option<u16> {
        match self {
            Self::None => None,
            Self::Http => Some(80),
            Self::Https => Some(443),
        }
    }
}

/// Reconcile Host metadata and request-target authority in distinct validation,
/// agreement, and selection phases.
pub fn reconcile_authority(
    target: &NormalizedTarget,
    headers: &HeaderBlock,
) -> Result<EffectiveAuthority> {
    let host_value = collect_host(headers)?;
    enforce_host_cardinality(&target.form, host_value)?;

    let default_port = target_default(target)?;
    let header_authority = host_value.map(parse_authority).transpose()?;
    let target_authority = target_authority(target)?;

    if let (Some(from_target), Some(from_header)) = (&target_authority, &header_authority)
        && !authorities_agree(from_target, from_header, default_port)
    {
        return Err(PolyguardError::AuthorityMismatch);
    }

    let chosen = target_authority
        .or(header_authority)
        .ok_or(PolyguardError::MissingHost)?;
    Ok(render_effective(chosen, default_port))
}

fn collect_host(headers: &HeaderBlock) -> Result<Option<&str>> {
    let mut found: Option<&[u8]> = None;

    for field in &headers.fields {
        if field.name != "host" {
            continue;
        }
        if found.is_some() {
            return Err(PolyguardError::MultipleHost);
        }
        found = Some(&field.value);
    }

    match found {
        Some(value) if value.contains(&b',') => classify_combined_host(value),
        Some(value) => std::str::from_utf8(value)
            .map(Some)
            .map_err(|_| PolyguardError::InvalidAuthority),
        None => Ok(None),
    }
}

fn classify_combined_host(value: &[u8]) -> Result<Option<&str>> {
    let mut members = value.split(|byte| *byte == b',');
    let first = members.next().unwrap_or_default();
    if !first.is_empty() && members.all(|member| member == first) {
        Err(PolyguardError::MultipleHost)
    } else {
        Err(PolyguardError::InvalidAuthority)
    }
}

fn enforce_host_cardinality(form: &TargetForm, host: Option<&str>) -> Result<()> {
    if matches!(form, TargetForm::Origin | TargetForm::Asterisk) && host.is_none() {
        Err(PolyguardError::MissingHost)
    } else {
        Ok(())
    }
}

fn target_default(target: &NormalizedTarget) -> Result<DefaultPort> {
    match (&target.form, target.scheme.as_deref()) {
        (TargetForm::Absolute, Some("http")) => Ok(DefaultPort::Http),
        (TargetForm::Absolute, Some("https")) => Ok(DefaultPort::Https),
        (TargetForm::Authority, None)
        | (TargetForm::Origin, None)
        | (TargetForm::Asterisk, None) => Ok(DefaultPort::None),
        _ => Err(PolyguardError::InvalidAuthority),
    }
}

fn target_authority(target: &NormalizedTarget) -> Result<Option<Authority>> {
    match (&target.form, target.authority.as_deref()) {
        (TargetForm::Absolute | TargetForm::Authority, Some(value)) => {
            parse_authority(value).map(Some)
        }
        (TargetForm::Origin | TargetForm::Asterisk, None) => Ok(None),
        _ => Err(PolyguardError::InvalidAuthority),
    }
}

fn authorities_agree(left: &Authority, right: &Authority, default: DefaultPort) -> bool {
    left.host == right.host
        && comparison_port(left.port, default) == comparison_port(right.port, default)
}

fn comparison_port(explicit: Option<u16>, default: DefaultPort) -> Option<u16> {
    explicit.or_else(|| default.number())
}

fn render_effective(authority: Authority, default: DefaultPort) -> EffectiveAuthority {
    let port = authority
        .port
        .filter(|port| Some(*port) != default.number());
    EffectiveAuthority {
        host: authority.host,
        port,
    }
}

fn parse_authority(input: &str) -> Result<Authority> {
    if input.is_empty()
        || !input.is_ascii()
        || input
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || input
            .bytes()
            .any(|byte| matches!(byte, b',' | b'@' | b'/' | b'?' | b'#' | b'%'))
    {
        return Err(PolyguardError::InvalidAuthority);
    }

    if input.starts_with('[') {
        parse_bracketed_ipv6(input)
    } else {
        parse_dns_authority(input)
    }
}

fn parse_bracketed_ipv6(input: &str) -> Result<Authority> {
    let closing = input.find(']').ok_or(PolyguardError::InvalidAuthority)?;
    let address = &input[1..closing];
    if address.is_empty() || address.parse::<Ipv6Addr>().is_err() {
        return Err(PolyguardError::InvalidAuthority);
    }

    let remainder = &input[closing + 1..];
    let port = if remainder.is_empty() {
        None
    } else {
        Some(parse_port(
            remainder
                .strip_prefix(':')
                .ok_or(PolyguardError::InvalidAuthority)?,
        )?)
    };

    let mut host = String::with_capacity(closing + 1);
    host.push('[');
    host.extend(
        address
            .chars()
            .map(|character| character.to_ascii_lowercase()),
    );
    host.push(']');
    Ok(Authority { host, port })
}

fn parse_dns_authority(input: &str) -> Result<Authority> {
    let (dns, port) = match input.split_once(':') {
        Some((dns, port)) if !port.contains(':') => (dns, Some(parse_port(port)?)),
        Some(_) => return Err(PolyguardError::InvalidAuthority),
        None => (input, None),
    };

    let canonical_dns = dns.strip_suffix('.').unwrap_or(dns);
    validate_dns(canonical_dns)?;
    Ok(Authority {
        host: canonical_dns.to_ascii_lowercase(),
        port,
    })
}

fn validate_dns(dns: &str) -> Result<()> {
    if dns.is_empty() || dns.len() > 253 {
        return Err(PolyguardError::InvalidAuthority);
    }

    for label in dns.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || bytes.first() == Some(&b'-')
            || bytes.last() == Some(&b'-')
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err(PolyguardError::InvalidAuthority);
        }
    }
    Ok(())
}

fn parse_port(port: &str) -> Result<u16> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PolyguardError::InvalidAuthority);
    }
    match port.parse::<u16>() {
        Ok(value @ 1..=u16::MAX) => Ok(value),
        _ => Err(PolyguardError::InvalidAuthority),
    }
}
