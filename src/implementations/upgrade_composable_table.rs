use std::collections::HashSet;

use crate::{BodyFraming, HeaderBlock, PolyguardError, RequestLine, Result, UpgradeDecision};

#[derive(Clone, Copy)]
enum Occurrence<T> {
    Missing,
    One(T),
    Repeated,
}

impl<T> Occurrence<T> {
    fn record(&mut self, value: T) {
        *self = match self {
            Self::Missing => Self::One(value),
            Self::One(_) | Self::Repeated => Self::Repeated,
        };
    }

    fn exists(&self) -> bool {
        !matches!(self, Self::Missing)
    }
}

#[derive(Clone, Copy)]
enum CheckedValue {
    Valid,
    Invalid,
}

#[derive(Clone, Copy)]
enum UpgradeIntent {
    Absent,
    OneSided,
    Paired,
}

#[derive(Clone, Copy)]
enum FramingSafety {
    Clear,
    BodyMetadata,
    Ambiguous,
}

#[derive(Clone, Copy)]
enum HandshakeShape {
    Complete,
    Incomplete,
}

struct UpgradeFields {
    connection: Occurrence<CheckedValue>,
    connection_has_upgrade: bool,
    upgrade: Occurrence<CheckedValue>,
    version: Occurrence<CheckedValue>,
    key: Occurrence<CheckedValue>,
    protocol: Occurrence<CheckedValue>,
    has_extensions: bool,
    has_content_length: bool,
    has_transfer_encoding: bool,
}

impl UpgradeFields {
    fn read(headers: &HeaderBlock) -> Self {
        let mut result = Self {
            connection: Occurrence::Missing,
            connection_has_upgrade: false,
            upgrade: Occurrence::Missing,
            version: Occurrence::Missing,
            key: Occurrence::Missing,
            protocol: Occurrence::Missing,
            has_extensions: false,
            has_content_length: false,
            has_transfer_encoding: false,
        };

        for field in &headers.fields {
            match field.name.as_str() {
                "connection" => {
                    let checked = inspect_connection(&field.value);
                    if matches!(checked, Some(true)) {
                        result.connection_has_upgrade = true;
                    }
                    result.connection.record(validity(checked.is_some()));
                }
                "upgrade" => result.upgrade.record(validity(
                    trim_ows(&field.value).eq_ignore_ascii_case(b"websocket"),
                )),
                "sec-websocket-version" => result
                    .version
                    .record(validity(trim_ows(&field.value) == b"13")),
                "sec-websocket-key" => result
                    .key
                    .record(validity(is_canonical_websocket_key(trim_ows(&field.value)))),
                "sec-websocket-protocol" => result
                    .protocol
                    .record(validity(valid_protocol_list(&field.value))),
                "sec-websocket-extensions" => result.has_extensions = true,
                "content-length" => result.has_content_length = true,
                "transfer-encoding" => result.has_transfer_encoding = true,
                _ => {}
            }
        }

        result
    }

    fn intent(&self) -> UpgradeIntent {
        match (self.upgrade.exists(), self.connection_has_upgrade) {
            (false, false) => UpgradeIntent::Absent,
            (true, true) => UpgradeIntent::Paired,
            (true, false) | (false, true) => UpgradeIntent::OneSided,
        }
    }

    fn framing_safety(&self, framing: &BodyFraming) -> FramingSafety {
        if self.has_content_length && self.has_transfer_encoding {
            FramingSafety::Ambiguous
        } else if self.has_content_length
            || self.has_transfer_encoding
            || !matches!(framing, BodyFraming::None)
        {
            FramingSafety::BodyMetadata
        } else {
            FramingSafety::Clear
        }
    }

    fn handshake_shape(&self, request: &RequestLine) -> HandshakeShape {
        let required_fields_are_unique_and_valid = matches!(
            (
                self.connection,
                self.upgrade,
                self.version,
                self.key,
                self.protocol,
            ),
            (
                Occurrence::One(CheckedValue::Valid),
                Occurrence::One(CheckedValue::Valid),
                Occurrence::One(CheckedValue::Valid),
                Occurrence::One(CheckedValue::Valid),
                Occurrence::Missing | Occurrence::One(CheckedValue::Valid),
            )
        );

        if required_fields_are_unique_and_valid
            && !self.has_extensions
            && request.method == "get"
            && is_origin_or_absolute(&request.target)
        {
            HandshakeShape::Complete
        } else {
            HandshakeShape::Incomplete
        }
    }
}

/// Recognize a complete WebSocket opening handshake through a centralized policy table.
pub fn decide_upgrade(
    request: &RequestLine,
    headers: &HeaderBlock,
    framing: &BodyFraming,
) -> Result<UpgradeDecision> {
    let fields = UpgradeFields::read(headers);
    let decision = (
        fields.intent(),
        fields.framing_safety(framing),
        fields.handshake_shape(request),
    );

    match decision {
        (UpgradeIntent::Absent, _, _) => Ok(UpgradeDecision::None),
        (_, FramingSafety::Ambiguous, _) => Err(PolyguardError::AmbiguousFraming),
        (UpgradeIntent::Paired, FramingSafety::Clear, HandshakeShape::Complete) => {
            Ok(UpgradeDecision::WebSocket)
        }
        (UpgradeIntent::OneSided | UpgradeIntent::Paired, _, _) => {
            Err(PolyguardError::UnsupportedUpgrade)
        }
    }
}

fn validity(condition: bool) -> CheckedValue {
    if condition {
        CheckedValue::Valid
    } else {
        CheckedValue::Invalid
    }
}

fn inspect_connection(value: &[u8]) -> Option<bool> {
    let mut contains_upgrade = false;
    for member in value.split(|byte| *byte == b',') {
        let token = trim_ows(member);
        if token.is_empty() || !token.iter().copied().all(is_token_byte) {
            return None;
        }
        contains_upgrade |= token.eq_ignore_ascii_case(b"upgrade");
    }
    Some(contains_upgrade)
}

fn valid_protocol_list(value: &[u8]) -> bool {
    let mut members = HashSet::new();
    for member in value.split(|byte| *byte == b',') {
        let token = trim_ows(member);
        if token.is_empty() || !token.iter().copied().all(is_token_byte) || !members.insert(token) {
            return false;
        }
    }
    true
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
            | b'0'..=b'9' | b'A'..=b'Z' | b'^' | b'_' | b'`' | b'a'..=b'z' | b'|' | b'~'
    )
}

fn is_canonical_websocket_key(value: &[u8]) -> bool {
    value.len() == 24
        && value[22..] == *b"=="
        && value[..22]
            .iter()
            .copied()
            .all(|byte| base64_digit(byte).is_some())
        && base64_digit(value[21]).is_some_and(|digit| digit & 0x0f == 0)
}

fn base64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn is_origin_or_absolute(target: &str) -> bool {
    target.starts_with('/')
        || target
            .as_bytes()
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
        || target
            .as_bytes()
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https://"))
}
