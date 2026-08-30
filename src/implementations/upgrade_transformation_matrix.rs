use std::collections::HashSet;

use crate::{BodyFraming, HeaderBlock, PolyguardError, RequestLine, Result, UpgradeDecision};

#[derive(Clone, Copy)]
enum Cardinality<T> {
    Missing,
    One(T),
    Duplicate,
}

#[derive(Clone, Copy)]
enum UpgradeProtocol {
    WebSocket,
    Other,
}

#[derive(Clone, Copy)]
struct ConnectionTokens {
    syntax_valid: bool,
    has_upgrade: bool,
}

#[derive(Clone, Copy)]
struct WebSocketKey([u8; 16]);

#[derive(Clone, Copy)]
enum Intent {
    Absent = 0,
    OneSided = 1,
    Paired = 2,
}

#[derive(Clone, Copy)]
enum FramingRisk {
    Clear = 0,
    Body = 1,
    Ambiguous = 2,
}

#[derive(Clone, Copy)]
enum HandshakeState {
    Incomplete = 0,
    Complete = 1,
}

#[derive(Clone, Copy)]
enum Outcome {
    None,
    WebSocket,
    Unsupported,
    Ambiguous,
}

// Indexed by intent, framing risk, then handshake completeness.  Keeping policy in one
// exhaustive matrix makes precedence visible: absent intent is always None, while ambiguous
// framing takes precedence over every attempted upgrade.
const DECISIONS: [[[Outcome; 2]; 3]; 3] = [
    [
        [Outcome::None, Outcome::None],
        [Outcome::None, Outcome::None],
        [Outcome::None, Outcome::None],
    ],
    [
        [Outcome::Unsupported, Outcome::Unsupported],
        [Outcome::Unsupported, Outcome::Unsupported],
        [Outcome::Ambiguous, Outcome::Ambiguous],
    ],
    [
        [Outcome::Unsupported, Outcome::WebSocket],
        [Outcome::Unsupported, Outcome::Unsupported],
        [Outcome::Ambiguous, Outcome::Ambiguous],
    ],
];

struct HandshakeParts {
    connection: Cardinality<ConnectionTokens>,
    connection_intent: bool,
    upgrade: Cardinality<UpgradeProtocol>,
    version: Cardinality<bool>,
    key: Cardinality<Option<WebSocketKey>>,
    protocols: Cardinality<bool>,
    extensions_present: bool,
    content_length_present: bool,
    transfer_encoding_present: bool,
}

impl HandshakeParts {
    fn transform(headers: &HeaderBlock) -> Self {
        Self {
            connection: transform_one(headers, "connection", parse_connection),
            connection_intent: headers
                .fields
                .iter()
                .filter(|field| field.name == "connection")
                .any(|field| parse_connection(&field.value).has_upgrade),
            upgrade: transform_one(headers, "upgrade", |value| {
                if trim_ows(value).eq_ignore_ascii_case(b"websocket") {
                    UpgradeProtocol::WebSocket
                } else {
                    UpgradeProtocol::Other
                }
            }),
            version: transform_one(headers, "sec-websocket-version", |value| {
                trim_ows(value) == b"13"
            }),
            key: transform_one(headers, "sec-websocket-key", |value| {
                decode_key(trim_ows(value))
            }),
            protocols: transform_one(headers, "sec-websocket-protocol", valid_protocols),
            extensions_present: has_header(headers, "sec-websocket-extensions"),
            content_length_present: has_header(headers, "content-length"),
            transfer_encoding_present: has_header(headers, "transfer-encoding"),
        }
    }

    fn intent(&self) -> Intent {
        let upgrade_field = !matches!(self.upgrade, Cardinality::Missing);
        match (upgrade_field, self.connection_intent) {
            (false, false) => Intent::Absent,
            (true, true) => Intent::Paired,
            (true, false) | (false, true) => Intent::OneSided,
        }
    }

    fn framing_risk(&self, framing: &BodyFraming) -> FramingRisk {
        match (
            self.content_length_present,
            self.transfer_encoding_present,
            framing,
        ) {
            (true, true, _) => FramingRisk::Ambiguous,
            (true, false, _) | (false, true, _) => FramingRisk::Body,
            (false, false, BodyFraming::None) => FramingRisk::Clear,
            (false, false, BodyFraming::ContentLength(_) | BodyFraming::Chunked) => {
                FramingRisk::Body
            }
        }
    }

    fn handshake_state(&self, request: &RequestLine) -> HandshakeState {
        let fields_complete =
            matches!(
                self.connection,
                Cardinality::One(ConnectionTokens {
                    syntax_valid: true,
                    has_upgrade: true,
                })
            ) && matches!(self.upgrade, Cardinality::One(UpgradeProtocol::WebSocket))
                && matches!(self.version, Cardinality::One(true))
                && valid_key(&self.key)
                && matches!(
                    self.protocols,
                    Cardinality::Missing | Cardinality::One(true)
                )
                && !self.extensions_present
                && !self.content_length_present
                && !self.transfer_encoding_present;

        if fields_complete && request.method == "get" && valid_target_form(&request.target) {
            HandshakeState::Complete
        } else {
            HandshakeState::Incomplete
        }
    }
}

fn valid_key(key: &Cardinality<Option<WebSocketKey>>) -> bool {
    matches!(key, Cardinality::One(Some(WebSocketKey(bytes))) if bytes.len() == 16)
}

/// Transform each handshake concern independently, then resolve it through one policy matrix.
pub fn decide_upgrade(
    request: &RequestLine,
    headers: &HeaderBlock,
    framing: &BodyFraming,
) -> Result<UpgradeDecision> {
    let parts = HandshakeParts::transform(headers);
    let outcome = DECISIONS[parts.intent() as usize][parts.framing_risk(framing) as usize]
        [parts.handshake_state(request) as usize];

    match outcome {
        Outcome::None => Ok(UpgradeDecision::None),
        Outcome::WebSocket => Ok(UpgradeDecision::WebSocket),
        Outcome::Unsupported => Err(PolyguardError::UnsupportedUpgrade),
        Outcome::Ambiguous => Err(PolyguardError::AmbiguousFraming),
    }
}

fn transform_one<T>(
    headers: &HeaderBlock,
    name: &str,
    transform: impl FnOnce(&[u8]) -> T,
) -> Cardinality<T> {
    let mut matches = headers.fields.iter().filter(|field| field.name == name);
    let Some(first) = matches.next() else {
        return Cardinality::Missing;
    };
    if matches.next().is_some() {
        return Cardinality::Duplicate;
    }
    Cardinality::One(transform(&first.value))
}

fn has_header(headers: &HeaderBlock, name: &str) -> bool {
    headers.fields.iter().any(|field| field.name == name)
}

fn parse_connection(value: &[u8]) -> ConnectionTokens {
    let mut syntax_valid = true;
    let mut has_upgrade = false;

    for raw in value.split(|byte| *byte == b',') {
        let token = trim_ows(raw);
        let valid = !token.is_empty() && token.iter().copied().all(is_token_byte);
        syntax_valid &= valid;
        has_upgrade |= valid && token.eq_ignore_ascii_case(b"upgrade");
    }

    ConnectionTokens {
        syntax_valid,
        has_upgrade,
    }
}

fn valid_protocols(value: &[u8]) -> bool {
    let mut seen = HashSet::new();
    value.split(|byte| *byte == b',').all(|raw| {
        let token = trim_ows(raw);
        !token.is_empty() && token.iter().copied().all(is_token_byte) && seen.insert(token)
    })
}

fn decode_key(encoded: &[u8]) -> Option<WebSocketKey> {
    if encoded.len() != 24 || encoded[22..] != *b"==" {
        return None;
    }

    let mut decoded = [0_u8; 16];
    for (source, destination) in (0..20).step_by(4).zip((0..15).step_by(3)) {
        let digits = decode_quartet(&encoded[source..source + 4])?;
        decoded[destination..destination + 3].copy_from_slice(&digits);
    }

    let high = base64_value(encoded[20])?;
    let low = base64_value(encoded[21])?;
    if low & 0x0f != 0 {
        return None;
    }
    decoded[15] = (high << 2) | (low >> 4);
    Some(WebSocketKey(decoded))
}

fn decode_quartet(encoded: &[u8]) -> Option<[u8; 3]> {
    let a = base64_value(encoded[0])?;
    let b = base64_value(encoded[1])?;
    let c = base64_value(encoded[2])?;
    let d = base64_value(encoded[3])?;
    Some([(a << 2) | (b >> 4), (b << 4) | (c >> 2), (c << 6) | d])
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
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

fn valid_target_form(target: &str) -> bool {
    target.starts_with('/')
        || target
            .as_bytes()
            .get(..7)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"http://"))
        || target
            .as_bytes()
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"https://"))
}
