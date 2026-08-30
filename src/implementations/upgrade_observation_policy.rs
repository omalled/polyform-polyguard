use std::collections::HashSet;

use crate::{BodyFraming, HeaderBlock, PolyguardError, RequestLine, Result, UpgradeDecision};

#[derive(Clone, Copy)]
struct ConnectionValue {
    well_formed: bool,
    requests_upgrade: bool,
}

#[derive(Clone, Copy)]
enum UpgradeValue {
    WebSocket,
    Other,
}

#[derive(Clone, Copy)]
enum HeaderObservation {
    Connection(ConnectionValue),
    Upgrade(UpgradeValue),
    Version13(bool),
    Key16(bool),
    ProtocolList(bool),
    Extensions,
    ContentLength,
    TransferEncoding,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Intent {
    Absent,
    OneSided,
    Paired,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FramingPolicy {
    Clear,
    Body,
    Ambiguous,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HandshakePolicy {
    Complete,
    Incomplete,
}

#[derive(Clone, Copy)]
enum IntentPattern {
    Absent,
    Present,
    Paired,
}

#[derive(Clone, Copy)]
enum FramingPattern {
    Any,
    Clear,
    Ambiguous,
}

#[derive(Clone, Copy)]
enum HandshakePattern {
    Any,
    Complete,
}

#[derive(Clone, Copy)]
enum PolicyResult {
    NoUpgrade,
    WebSocket,
    Unsupported,
    Ambiguous,
}

enum OptionalValue<T> {
    Missing,
    One(T),
    Repeated,
}

#[derive(Clone, Copy)]
struct DecisionRow {
    intent: IntentPattern,
    framing: FramingPattern,
    handshake: HandshakePattern,
    result: PolicyResult,
}

const DECISION_TABLE: [DecisionRow; 4] = [
    DecisionRow {
        intent: IntentPattern::Absent,
        framing: FramingPattern::Any,
        handshake: HandshakePattern::Any,
        result: PolicyResult::NoUpgrade,
    },
    DecisionRow {
        intent: IntentPattern::Present,
        framing: FramingPattern::Ambiguous,
        handshake: HandshakePattern::Any,
        result: PolicyResult::Ambiguous,
    },
    DecisionRow {
        intent: IntentPattern::Paired,
        framing: FramingPattern::Clear,
        handshake: HandshakePattern::Complete,
        result: PolicyResult::WebSocket,
    },
    DecisionRow {
        intent: IntentPattern::Present,
        framing: FramingPattern::Any,
        handshake: HandshakePattern::Any,
        result: PolicyResult::Unsupported,
    },
];

/// Classify header values independently, then resolve the request through one policy table.
pub fn decide_upgrade(
    request: &RequestLine,
    headers: &HeaderBlock,
    framing: &BodyFraming,
) -> Result<UpgradeDecision> {
    let observations: Vec<_> = headers
        .fields
        .iter()
        .filter_map(|field| observe_header(&field.name, &field.value))
        .collect();

    let intent = classify_intent(&observations);
    let framing = classify_framing(&observations, framing);
    let handshake = classify_handshake(request, &observations);

    let outcome = DECISION_TABLE
        .iter()
        .find(|row| row.applies(intent, framing, handshake))
        .expect("decision table covers every upgrade state")
        .result;

    match outcome {
        PolicyResult::NoUpgrade => Ok(UpgradeDecision::None),
        PolicyResult::WebSocket => Ok(UpgradeDecision::WebSocket),
        PolicyResult::Unsupported => Err(PolyguardError::UnsupportedUpgrade),
        PolicyResult::Ambiguous => Err(PolyguardError::AmbiguousFraming),
    }
}

impl DecisionRow {
    fn applies(self, intent: Intent, framing: FramingPolicy, handshake: HandshakePolicy) -> bool {
        let intent_matches = match self.intent {
            IntentPattern::Absent => intent == Intent::Absent,
            IntentPattern::Present => intent != Intent::Absent,
            IntentPattern::Paired => intent == Intent::Paired,
        };
        let framing_matches = match self.framing {
            FramingPattern::Any => true,
            FramingPattern::Clear => framing == FramingPolicy::Clear,
            FramingPattern::Ambiguous => framing == FramingPolicy::Ambiguous,
        };
        let handshake_matches = match self.handshake {
            HandshakePattern::Any => true,
            HandshakePattern::Complete => handshake == HandshakePolicy::Complete,
        };

        intent_matches && framing_matches && handshake_matches
    }
}

fn observe_header(name: &str, value: &[u8]) -> Option<HeaderObservation> {
    match name {
        "connection" => Some(HeaderObservation::Connection(parse_connection(value))),
        "upgrade" => Some(HeaderObservation::Upgrade(
            if trim_ows(value).eq_ignore_ascii_case(b"websocket") {
                UpgradeValue::WebSocket
            } else {
                UpgradeValue::Other
            },
        )),
        "sec-websocket-version" => Some(HeaderObservation::Version13(trim_ows(value) == b"13")),
        "sec-websocket-key" => Some(HeaderObservation::Key16(
            decode_canonical_key(trim_ows(value)).is_some(),
        )),
        "sec-websocket-protocol" => Some(HeaderObservation::ProtocolList(validate_protocol_list(
            value,
        ))),
        "sec-websocket-extensions" => Some(HeaderObservation::Extensions),
        "content-length" => Some(HeaderObservation::ContentLength),
        "transfer-encoding" => Some(HeaderObservation::TransferEncoding),
        _ => None,
    }
}

fn classify_intent(observations: &[HeaderObservation]) -> Intent {
    let upgrade_field = observations
        .iter()
        .any(|item| matches!(item, HeaderObservation::Upgrade(_)));
    let connection_token = observations.iter().any(|item| {
        matches!(
            item,
            HeaderObservation::Connection(ConnectionValue {
                well_formed: true,
                requests_upgrade: true,
            })
        )
    });

    match (upgrade_field, connection_token) {
        (false, false) => Intent::Absent,
        (true, true) => Intent::Paired,
        (true, false) | (false, true) => Intent::OneSided,
    }
}

fn classify_framing(observations: &[HeaderObservation], framing: &BodyFraming) -> FramingPolicy {
    let content_length = observations
        .iter()
        .any(|item| matches!(item, HeaderObservation::ContentLength));
    let transfer_encoding = observations
        .iter()
        .any(|item| matches!(item, HeaderObservation::TransferEncoding));

    if content_length && transfer_encoding {
        FramingPolicy::Ambiguous
    } else if content_length || transfer_encoding || !matches!(framing, BodyFraming::None) {
        FramingPolicy::Body
    } else {
        FramingPolicy::Clear
    }
}

fn classify_handshake(
    request: &RequestLine,
    observations: &[HeaderObservation],
) -> HandshakePolicy {
    let connection = exactly_one(observations.iter().filter_map(|item| match item {
        HeaderObservation::Connection(value) => Some(*value),
        _ => None,
    }));
    let upgrade = exactly_one(observations.iter().filter_map(|item| match item {
        HeaderObservation::Upgrade(value) => Some(*value),
        _ => None,
    }));
    let version = exactly_one(observations.iter().filter_map(|item| match item {
        HeaderObservation::Version13(valid) => Some(*valid),
        _ => None,
    }));
    let key = exactly_one(observations.iter().filter_map(|item| match item {
        HeaderObservation::Key16(valid) => Some(*valid),
        _ => None,
    }));
    let protocols = optional_one(observations.iter().filter_map(|item| match item {
        HeaderObservation::ProtocolList(valid) => Some(*valid),
        _ => None,
    }));
    let forbidden = observations.iter().any(|item| {
        matches!(
            item,
            HeaderObservation::Extensions
                | HeaderObservation::ContentLength
                | HeaderObservation::TransferEncoding
        )
    });

    let complete = matches!(
        connection,
        Some(ConnectionValue {
            well_formed: true,
            requests_upgrade: true
        })
    ) && matches!(upgrade, Some(UpgradeValue::WebSocket))
        && version == Some(true)
        && key == Some(true)
        && matches!(protocols, OptionalValue::Missing | OptionalValue::One(true))
        && !forbidden
        && request.method == "get"
        && permitted_target(&request.target);

    if complete {
        HandshakePolicy::Complete
    } else {
        HandshakePolicy::Incomplete
    }
}

fn exactly_one<T>(mut values: impl Iterator<Item = T>) -> Option<T> {
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn optional_one<T>(mut values: impl Iterator<Item = T>) -> OptionalValue<T> {
    match (values.next(), values.next()) {
        (None, _) => OptionalValue::Missing,
        (Some(value), None) => OptionalValue::One(value),
        (Some(_), Some(_)) => OptionalValue::Repeated,
    }
}

fn parse_connection(value: &[u8]) -> ConnectionValue {
    let mut requests_upgrade = false;
    for member in value.split(|byte| *byte == b',') {
        let token = trim_ows(member);
        if token.is_empty() || !token.iter().copied().all(is_token_byte) {
            return ConnectionValue {
                well_formed: false,
                requests_upgrade: false,
            };
        }
        requests_upgrade |= token.eq_ignore_ascii_case(b"upgrade");
    }

    ConnectionValue {
        well_formed: true,
        requests_upgrade,
    }
}

fn validate_protocol_list(value: &[u8]) -> bool {
    let mut tokens = HashSet::new();
    for member in value.split(|byte| *byte == b',') {
        let token = trim_ows(member);
        if token.is_empty() || !token.iter().copied().all(is_token_byte) || !tokens.insert(token) {
            return false;
        }
    }
    true
}

fn decode_canonical_key(encoded: &[u8]) -> Option<[u8; 16]> {
    if encoded.len() != 24 || encoded[22..] != *b"==" {
        return None;
    }

    let mut decoded = [0_u8; 16];
    let mut output = 0;
    for start in [0, 4, 8, 12, 16] {
        let quartet = &encoded[start..start + 4];
        let a = base64_value(quartet[0])?;
        let b = base64_value(quartet[1])?;
        let c = base64_value(quartet[2])?;
        let d = base64_value(quartet[3])?;
        decoded[output] = (a << 2) | (b >> 4);
        decoded[output + 1] = (b << 4) | (c >> 2);
        decoded[output + 2] = (c << 6) | d;
        output += 3;
    }

    let a = base64_value(encoded[20])?;
    let b = base64_value(encoded[21])?;
    if b & 0x0f != 0 {
        return None;
    }
    decoded[15] = (a << 2) | (b >> 4);
    Some(decoded)
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

fn permitted_target(target: &str) -> bool {
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
