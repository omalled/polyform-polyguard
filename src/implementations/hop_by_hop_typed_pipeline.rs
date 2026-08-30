use std::collections::BTreeSet;

use crate::{HeaderBlock, HeaderField, PolyguardError, Result, SanitizedHeaders};

#[derive(Clone, Copy)]
enum RuleEffect {
    Drop,
    ReadConnectionTokens,
}

#[derive(Clone, Copy)]
struct HeaderRule {
    name: &'static str,
    effect: RuleEffect,
}

const HEADER_RULES: [HeaderRule; 9] = [
    HeaderRule {
        name: "connection",
        effect: RuleEffect::ReadConnectionTokens,
    },
    HeaderRule {
        name: "proxy-connection",
        effect: RuleEffect::Drop,
    },
    HeaderRule {
        name: "keep-alive",
        effect: RuleEffect::Drop,
    },
    HeaderRule {
        name: "transfer-encoding",
        effect: RuleEffect::Drop,
    },
    HeaderRule {
        name: "te",
        effect: RuleEffect::Drop,
    },
    HeaderRule {
        name: "trailer",
        effect: RuleEffect::Drop,
    },
    HeaderRule {
        name: "upgrade",
        effect: RuleEffect::Drop,
    },
    HeaderRule {
        name: "proxy-authenticate",
        effect: RuleEffect::Drop,
    },
    HeaderRule {
        name: "proxy-authorization",
        effect: RuleEffect::Drop,
    },
];

enum HeaderEvent<'a> {
    EndToEnd,
    FixedHopByHop(&'static str),
    Connection { index: usize, value: &'a [u8] },
}

impl<'a> HeaderEvent<'a> {
    fn classify(index: usize, field: &'a HeaderField) -> Self {
        match HEADER_RULES.iter().find(|rule| rule.name == field.name) {
            None => Self::EndToEnd,
            Some(HeaderRule {
                name,
                effect: RuleEffect::Drop,
            }) => Self::FixedHopByHop(name),
            Some(HeaderRule {
                effect: RuleEffect::ReadConnectionTokens,
                ..
            }) => Self::Connection {
                index,
                value: &field.value,
            },
        }
    }
}

#[derive(Default)]
struct RemovalLedger {
    names: BTreeSet<String>,
}

impl RemovalLedger {
    fn apply(mut self, event: HeaderEvent<'_>) -> Result<Self> {
        match event {
            HeaderEvent::EndToEnd => {}
            HeaderEvent::FixedHopByHop(name) => {
                self.names.insert(name.to_owned());
            }
            HeaderEvent::Connection { index, value } => {
                self.names.insert("connection".to_owned());
                self = ConnectionMembers::new(value).try_fold(self, |mut ledger, member| {
                    let member = member.map_err(|()| invalid_connection_token(index))?;
                    ledger.names.insert(lowercase_token(member));
                    Ok(ledger)
                })?;
            }
        }
        Ok(self)
    }
}

#[derive(Clone, Copy)]
enum ScanPosition {
    MemberStart(usize),
    Complete,
    Rejected,
}

struct ConnectionMembers<'a> {
    value: &'a [u8],
    position: ScanPosition,
}

impl<'a> ConnectionMembers<'a> {
    fn new(value: &'a [u8]) -> Self {
        Self {
            value,
            position: ScanPosition::MemberStart(0),
        }
    }
}

impl<'a> Iterator for ConnectionMembers<'a> {
    type Item = std::result::Result<&'a [u8], ()>;

    fn next(&mut self) -> Option<Self::Item> {
        let ScanPosition::MemberStart(mut cursor) = self.position else {
            return None;
        };

        cursor += self.value[cursor..]
            .iter()
            .take_while(|byte| is_ows(**byte))
            .count();
        let token_start = cursor;
        cursor += self.value[cursor..]
            .iter()
            .take_while(|byte| is_token_byte(**byte))
            .count();
        let token_end = cursor;
        cursor += self.value[cursor..]
            .iter()
            .take_while(|byte| is_ows(**byte))
            .count();

        if token_start == token_end {
            self.position = ScanPosition::Rejected;
            return Some(Err(()));
        }

        self.position = match self.value.get(cursor) {
            None => ScanPosition::Complete,
            Some(b',') => ScanPosition::MemberStart(cursor + 1),
            Some(_) => {
                self.position = ScanPosition::Rejected;
                return Some(Err(()));
            }
        };

        Some(Ok(&self.value[token_start..token_end]))
    }
}

/// Remove fixed hop-by-hop fields and all fields nominated by validated
/// `Connection` list members, preserving end-to-end field order and bytes.
pub(crate) fn remove_hop_by_hop_headers(headers: &HeaderBlock) -> Result<SanitizedHeaders> {
    let ledger = headers
        .fields
        .iter()
        .enumerate()
        .map(|(index, field)| HeaderEvent::classify(index, field))
        .try_fold(RemovalLedger::default(), RemovalLedger::apply)?;

    let fields = headers
        .fields
        .iter()
        .filter(|field| !ledger.names.contains(field.name.as_str()))
        .cloned()
        .collect();

    Ok(SanitizedHeaders {
        fields,
        removed_names: ledger.names.into_iter().collect(),
    })
}

fn lowercase_token(token: &[u8]) -> String {
    token
        .iter()
        .map(u8::to_ascii_lowercase)
        .map(char::from)
        .collect()
}

fn is_ows(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn invalid_connection_token(index: usize) -> PolyguardError {
    PolyguardError::InvalidHeader {
        index,
        reason: "invalid_connection_token".to_owned(),
    }
}
