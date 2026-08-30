use crate::{BodyFraming, HeaderBlock, PolyguardError, RequestLine, Result, UpgradeDecision};

const CONNECTION: usize = 0;
const UPGRADE: usize = 1;
const VERSION: usize = 2;
const KEY: usize = 3;
const PROTOCOL: usize = 4;
const EXTENSIONS: usize = 5;
const CONTENT_LENGTH: usize = 6;
const TRANSFER_ENCODING: usize = 7;

const REQUIRED_ONCE: u16 = bit(CONNECTION) | bit(UPGRADE) | bit(VERSION) | bit(KEY);
const UNIQUE_FIELDS: u16 = REQUIRED_ONCE | bit(PROTOCOL);
const FORBIDDEN_FIELDS: u16 = bit(EXTENSIONS) | bit(CONTENT_LENGTH) | bit(TRANSFER_ENCODING);

const HEADER_LOOKUP: [(&str, usize); 8] = [
    ("connection", CONNECTION),
    ("upgrade", UPGRADE),
    ("sec-websocket-version", VERSION),
    ("sec-websocket-key", KEY),
    ("sec-websocket-protocol", PROTOCOL),
    ("sec-websocket-extensions", EXTENSIONS),
    ("content-length", CONTENT_LENGTH),
    ("transfer-encoding", TRANSFER_ENCODING),
];

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fn bit(index: usize) -> u16 {
    1 << index
}

#[derive(Default)]
struct HeaderSignature {
    seen: u16,
    duplicates: u16,
    invalid: u16,
    connection_upgrade: bool,
}

impl HeaderSignature {
    /// Validate all handshake-specific values while crossing the public boundary.  Policy
    /// evaluation subsequently depends only on this compact, trusted signature.
    fn validate(headers: &HeaderBlock) -> Self {
        let mut signature = Self::default();

        for field in &headers.fields {
            let Some(kind) = HEADER_LOOKUP
                .iter()
                .find_map(|(name, kind)| (field.name == *name).then_some(*kind))
            else {
                continue;
            };

            let marker = bit(kind);
            if signature.seen & marker == 0 {
                signature.seen |= marker;
            } else {
                signature.duplicates |= marker;
            }

            let (valid, carries_connection_intent) = match kind {
                CONNECTION => validate_connection(&field.value),
                UPGRADE => (
                    trim_ows(&field.value).eq_ignore_ascii_case(b"websocket"),
                    false,
                ),
                VERSION => (trim_ows(&field.value) == b"13", false),
                KEY => (
                    decode_canonical_key(trim_ows(&field.value)).is_some(),
                    false,
                ),
                PROTOCOL => (validate_protocols(&field.value), false),
                EXTENSIONS | CONTENT_LENGTH | TRANSFER_ENCODING => (true, false),
                _ => unreachable!("header lookup contains only declared kinds"),
            };

            if !valid {
                signature.invalid |= marker;
            }
            signature.connection_upgrade |= carries_connection_intent;
        }

        signature
    }

    fn has(&self, kind: usize) -> bool {
        self.seen & bit(kind) != 0
    }

    fn is_complete(&self, request: &RequestLine) -> bool {
        self.seen & REQUIRED_ONCE == REQUIRED_ONCE
            && self.duplicates & UNIQUE_FIELDS == 0
            && self.invalid & UNIQUE_FIELDS == 0
            && self.seen & FORBIDDEN_FIELDS == 0
            && self.connection_upgrade
            && request.method == "get"
            && permitted_target(&request.target)
    }
}

#[derive(Clone, Copy)]
enum Intent {
    Absent,
    OneSided,
    Paired,
}

#[derive(Clone, Copy)]
enum FramingState {
    Clear,
    Body,
    Ambiguous,
}

/// Decide upgrade policy from a validated header signature and handshake invariants.
pub fn decide_upgrade(
    request: &RequestLine,
    headers: &HeaderBlock,
    framing: &BodyFraming,
) -> Result<UpgradeDecision> {
    let signature = HeaderSignature::validate(headers);

    let intent = match (signature.has(UPGRADE), signature.connection_upgrade) {
        (false, false) => Intent::Absent,
        (true, true) => Intent::Paired,
        (false, true) | (true, false) => Intent::OneSided,
    };
    let framing_state = match (
        signature.has(CONTENT_LENGTH),
        signature.has(TRANSFER_ENCODING),
        framing,
    ) {
        (true, true, _) => FramingState::Ambiguous,
        (true, false, _) | (false, true, _) => FramingState::Body,
        (false, false, BodyFraming::None) => FramingState::Clear,
        (false, false, BodyFraming::ContentLength(_) | BodyFraming::Chunked) => FramingState::Body,
    };

    match (intent, framing_state, signature.is_complete(request)) {
        (Intent::Absent, FramingState::Clear | FramingState::Body | FramingState::Ambiguous, _) => {
            Ok(UpgradeDecision::None)
        }
        (Intent::OneSided | Intent::Paired, FramingState::Ambiguous, _) => {
            Err(PolyguardError::AmbiguousFraming)
        }
        (Intent::Paired, FramingState::Clear, true) => Ok(UpgradeDecision::WebSocket),
        (Intent::OneSided, FramingState::Clear, true) => Err(PolyguardError::UnsupportedUpgrade),
        (Intent::OneSided | Intent::Paired, FramingState::Clear | FramingState::Body, false)
        | (Intent::OneSided | Intent::Paired, FramingState::Body, true) => {
            Err(PolyguardError::UnsupportedUpgrade)
        }
    }
}

fn validate_connection(value: &[u8]) -> (bool, bool) {
    let mut has_upgrade = false;
    for member in value.split(|byte| *byte == b',') {
        let token = trim_ows(member);
        if token.is_empty() || !token.iter().copied().all(is_token_byte) {
            return (false, false);
        }
        has_upgrade |= token.eq_ignore_ascii_case(b"upgrade");
    }
    (true, has_upgrade)
}

fn validate_protocols(value: &[u8]) -> bool {
    let mut unique = TokenTrie::new();
    value.split(|byte| *byte == b',').all(|member| {
        let token = trim_ows(member);
        !token.is_empty() && token.iter().copied().all(is_token_byte) && unique.insert(token)
    })
}

struct TrieNode {
    first_edge: Option<usize>,
    terminal: bool,
}

struct TrieEdge {
    byte: u8,
    child: usize,
    sibling: Option<usize>,
}

struct TokenTrie {
    nodes: Vec<TrieNode>,
    edges: Vec<TrieEdge>,
}

impl TokenTrie {
    fn new() -> Self {
        Self {
            nodes: vec![TrieNode {
                first_edge: None,
                terminal: false,
            }],
            edges: Vec::new(),
        }
    }

    fn insert(&mut self, token: &[u8]) -> bool {
        let mut node = 0;
        for &byte in token {
            let mut edge = self.nodes[node].first_edge;
            let mut child = None;
            while let Some(index) = edge {
                if self.edges[index].byte == byte {
                    child = Some(self.edges[index].child);
                    break;
                }
                edge = self.edges[index].sibling;
            }

            node = child.unwrap_or_else(|| {
                let child = self.nodes.len();
                self.nodes.push(TrieNode {
                    first_edge: None,
                    terminal: false,
                });
                let new_edge = self.edges.len();
                self.edges.push(TrieEdge {
                    byte,
                    child,
                    sibling: self.nodes[node].first_edge,
                });
                self.nodes[node].first_edge = Some(new_edge);
                child
            });
        }

        let was_new = !self.nodes[node].terminal;
        self.nodes[node].terminal = true;
        was_new
    }
}

fn decode_canonical_key(encoded: &[u8]) -> Option<[u8; 16]> {
    if encoded.len() != 24 || encoded[22..] != *b"==" {
        return None;
    }

    let mut decoded = [0_u8; 16];
    for group in 0..5 {
        let source = group * 4;
        let target = group * 3;
        let digits = [
            base64_value(encoded[source])?,
            base64_value(encoded[source + 1])?,
            base64_value(encoded[source + 2])?,
            base64_value(encoded[source + 3])?,
        ];
        decoded[target] = (digits[0] << 2) | (digits[1] >> 4);
        decoded[target + 1] = (digits[1] << 4) | (digits[2] >> 2);
        decoded[target + 2] = (digits[2] << 6) | digits[3];
    }

    let high = base64_value(encoded[20])?;
    let low = base64_value(encoded[21])?;
    if low & 0x0f != 0 {
        return None;
    }
    decoded[15] = (high << 2) | (low >> 4);
    Some(decoded)
}

fn base64_value(byte: u8) -> Option<u8> {
    BASE64_ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u8)
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
    let bytes = target.as_bytes();
    bytes.starts_with(b"/")
        || bytes
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
        || bytes
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https://"))
}
