use std::collections::HashSet;

use crate::{BodyFraming, HeaderBlock, PolyguardError, RequestLine, Result, UpgradeDecision};

const CONNECTION: &str = "connection";
const UPGRADE: &str = "upgrade";
const VERSION: &str = "sec-websocket-version";
const KEY: &str = "sec-websocket-key";
const PROTOCOL: &str = "sec-websocket-protocol";
const EXTENSIONS: &str = "sec-websocket-extensions";
const CONTENT_LENGTH: &str = "content-length";
const TRANSFER_ENCODING: &str = "transfer-encoding";

const WEBSOCKET: &[u8] = b"websocket";
const VERSION_13: &[u8] = b"13";
const ENCODED_KEY_BYTES: usize = 24;
const KEY_DATA_BYTES: usize = 22;
const INVALID_BASE64: u8 = u8::MAX;
const BASE64_VALUES: [u8; 256] = base64_values();

#[derive(Clone, Copy)]
enum Obligation {
    Open,
    Discharged,
    Contradicted,
}

impl Obligation {
    fn supply(&mut self, valid: bool) {
        *self = match (*self, valid) {
            (Self::Open, true) => Self::Discharged,
            (Self::Open, false)
            | (Self::Discharged, true | false)
            | (Self::Contradicted, true | false) => Self::Contradicted,
        };
    }
}

struct BoundaryFacts {
    connection: Obligation,
    upgrade: Obligation,
    version: Obligation,
    key: Obligation,
    protocol: Obligation,
    upgrade_field_present: bool,
    connection_upgrade_present: bool,
    extensions_present: bool,
    content_length_present: bool,
    transfer_encoding_present: bool,
}

impl BoundaryFacts {
    fn validate(headers: &HeaderBlock) -> Self {
        let mut facts = Self {
            connection: Obligation::Open,
            upgrade: Obligation::Open,
            version: Obligation::Open,
            key: Obligation::Open,
            protocol: Obligation::Open,
            upgrade_field_present: false,
            connection_upgrade_present: false,
            extensions_present: false,
            content_length_present: false,
            transfer_encoding_present: false,
        };

        for field in &headers.fields {
            match field.name.as_str() {
                CONNECTION => {
                    let connection = validate_connection(&field.value);
                    facts
                        .connection
                        .supply(connection == ConnectionEvidence::Upgrade);
                    facts.connection_upgrade_present |= connection == ConnectionEvidence::Upgrade;
                }
                UPGRADE => {
                    facts.upgrade_field_present = true;
                    facts
                        .upgrade
                        .supply(trim_ows(&field.value).eq_ignore_ascii_case(WEBSOCKET));
                }
                VERSION => facts.version.supply(trim_ows(&field.value) == VERSION_13),
                KEY => facts.key.supply(canonical_key(trim_ows(&field.value))),
                PROTOCOL => facts.protocol.supply(unique_protocols(&field.value)),
                EXTENSIONS => facts.extensions_present = true,
                CONTENT_LENGTH => facts.content_length_present = true,
                TRANSFER_ENCODING => facts.transfer_encoding_present = true,
                _ => {}
            }
        }

        facts
    }

    fn intent(&self) -> Intent {
        match (self.upgrade_field_present, self.connection_upgrade_present) {
            (false, false) => Intent::Absent,
            (true, true) => Intent::Complete,
            (false, true) | (true, false) => Intent::Partial,
        }
    }

    fn framing(&self, framing: &BodyFraming) -> FramingEvidence {
        match (
            self.content_length_present,
            self.transfer_encoding_present,
            framing,
        ) {
            (
                true,
                true,
                BodyFraming::None | BodyFraming::ContentLength(_) | BodyFraming::Chunked,
            ) => FramingEvidence::Ambiguous,
            (
                true,
                false,
                BodyFraming::None | BodyFraming::ContentLength(_) | BodyFraming::Chunked,
            )
            | (
                false,
                true,
                BodyFraming::None | BodyFraming::ContentLength(_) | BodyFraming::Chunked,
            )
            | (false, false, BodyFraming::ContentLength(_) | BodyFraming::Chunked) => {
                FramingEvidence::Body
            }
            (false, false, BodyFraming::None) => FramingEvidence::Clear,
        }
    }

    fn handshake(&self, request: &RequestLine) -> HandshakeEvidence {
        match (
            self.connection,
            self.upgrade,
            self.version,
            self.key,
            self.protocol,
            self.extensions_present,
            self.content_length_present,
            self.transfer_encoding_present,
            request.method.as_str(),
            target_form(&request.target),
        ) {
            (
                Obligation::Discharged,
                Obligation::Discharged,
                Obligation::Discharged,
                Obligation::Discharged,
                Obligation::Open | Obligation::Discharged,
                false,
                false,
                false,
                "get",
                TargetEvidence::Origin | TargetEvidence::Absolute,
            ) => HandshakeEvidence::Complete,
            (
                Obligation::Open | Obligation::Discharged | Obligation::Contradicted,
                Obligation::Open | Obligation::Discharged | Obligation::Contradicted,
                Obligation::Open | Obligation::Discharged | Obligation::Contradicted,
                Obligation::Open | Obligation::Discharged | Obligation::Contradicted,
                Obligation::Open | Obligation::Discharged | Obligation::Contradicted,
                true | false,
                true | false,
                true | false,
                _,
                TargetEvidence::Origin | TargetEvidence::Absolute | TargetEvidence::Other,
            ) => HandshakeEvidence::Incomplete,
        }
    }
}

#[derive(Clone, Copy)]
enum Intent {
    Absent,
    Partial,
    Complete,
}

#[derive(Clone, Copy)]
enum FramingEvidence {
    Clear,
    Body,
    Ambiguous,
}

#[derive(Clone, Copy)]
enum HandshakeEvidence {
    Complete,
    Incomplete,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionEvidence {
    Upgrade,
    NoUpgrade,
    Invalid,
}

#[derive(Clone, Copy)]
enum TargetEvidence {
    Origin,
    Absolute,
    Other,
}

/// Validate boundary evidence, then solve the upgrade obligations exhaustively.
pub fn decide_upgrade(
    request: &RequestLine,
    headers: &HeaderBlock,
    framing: &BodyFraming,
) -> Result<UpgradeDecision> {
    let facts = BoundaryFacts::validate(headers);

    match (
        facts.intent(),
        facts.framing(framing),
        facts.handshake(request),
    ) {
        (
            Intent::Absent,
            FramingEvidence::Clear | FramingEvidence::Body | FramingEvidence::Ambiguous,
            _,
        ) => Ok(UpgradeDecision::None),
        (Intent::Partial | Intent::Complete, FramingEvidence::Ambiguous, _) => {
            Err(PolyguardError::AmbiguousFraming)
        }
        (Intent::Complete, FramingEvidence::Clear, HandshakeEvidence::Complete) => {
            Ok(UpgradeDecision::WebSocket)
        }
        (
            Intent::Partial | Intent::Complete,
            FramingEvidence::Clear | FramingEvidence::Body,
            HandshakeEvidence::Complete | HandshakeEvidence::Incomplete,
        ) => Err(PolyguardError::UnsupportedUpgrade),
    }
}

fn validate_connection(value: &[u8]) -> ConnectionEvidence {
    let mut upgrade = false;
    for raw in value.split(|byte| *byte == b',') {
        let token = trim_ows(raw);
        match (
            !token.is_empty() && token.iter().copied().all(token_byte),
            token.eq_ignore_ascii_case(b"upgrade"),
        ) {
            (true, true) => upgrade = true,
            (true, false) => {}
            (false, true | false) => return ConnectionEvidence::Invalid,
        }
    }
    match upgrade {
        true => ConnectionEvidence::Upgrade,
        false => ConnectionEvidence::NoUpgrade,
    }
}

fn unique_protocols(value: &[u8]) -> bool {
    let mut seen = HashSet::new();
    for raw in value.split(|byte| *byte == b',') {
        let token = trim_ows(raw);
        match (
            !token.is_empty(),
            token.iter().copied().all(token_byte),
            seen.insert(token),
        ) {
            (true, true, true) => {}
            (false, true | false, true | false)
            | (true, false, true | false)
            | (true, true, false) => return false,
        }
    }
    true
}

fn canonical_key(encoded: &[u8]) -> bool {
    match encoded {
        value if value.len() != ENCODED_KEY_BYTES => false,
        value if value[KEY_DATA_BYTES..] != *b"==" => false,
        value => {
            let digits_are_base64 = value[..KEY_DATA_BYTES]
                .iter()
                .all(|byte| BASE64_VALUES[*byte as usize] != INVALID_BASE64);
            let unused_low_bits_are_zero =
                BASE64_VALUES[value[KEY_DATA_BYTES - 1] as usize] & 0x0f == 0;
            digits_are_base64 && unused_low_bits_are_zero
        }
    }
}

const fn base64_values() -> [u8; 256] {
    let mut values = [INVALID_BASE64; 256];
    let mut index = 0;
    while index < 26 {
        values[b'A' as usize + index] = index as u8;
        values[b'a' as usize + index] = index as u8 + 26;
        index += 1;
    }
    index = 0;
    while index < 10 {
        values[b'0' as usize + index] = index as u8 + 52;
        index += 1;
    }
    values[b'+' as usize] = 62;
    values[b'/' as usize] = 63;
    values
}

fn target_form(target: &str) -> TargetEvidence {
    match target.as_bytes() {
        [b'/', ..] => TargetEvidence::Origin,
        bytes
            if bytes
                .get(..7)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"http://"))
                || bytes
                    .get(..8)
                    .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"https://")) =>
        {
            TargetEvidence::Absolute
        }
        _ => TargetEvidence::Other,
    }
}

fn trim_ows(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |index| index + 1);
    &value[start..end]
}

fn token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
            | b'0'..=b'9' | b'A'..=b'Z' | b'^' | b'_' | b'`' | b'a'..=b'z' | b'|' | b'~'
    )
}
