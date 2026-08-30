use crate::{HeaderBlock, PolyguardError, Result, SanitizedHeaders};

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderAction {
    Remove,
    RemoveAndNominate,
}

#[derive(Clone, Copy)]
struct HeaderRule {
    name: &'static str,
    action: HeaderAction,
}

const HEADER_RULES: [HeaderRule; 9] = [
    HeaderRule {
        name: "connection",
        action: HeaderAction::RemoveAndNominate,
    },
    HeaderRule {
        name: "proxy-connection",
        action: HeaderAction::Remove,
    },
    HeaderRule {
        name: "keep-alive",
        action: HeaderAction::Remove,
    },
    HeaderRule {
        name: "transfer-encoding",
        action: HeaderAction::Remove,
    },
    HeaderRule {
        name: "te",
        action: HeaderAction::Remove,
    },
    HeaderRule {
        name: "trailer",
        action: HeaderAction::Remove,
    },
    HeaderRule {
        name: "upgrade",
        action: HeaderAction::Remove,
    },
    HeaderRule {
        name: "proxy-authenticate",
        action: HeaderAction::Remove,
    },
    HeaderRule {
        name: "proxy-authorization",
        action: HeaderAction::Remove,
    },
];

enum ConnectionMember<'a> {
    Token(&'a [u8]),
    Empty,
    Invalid,
}

impl<'a> ConnectionMember<'a> {
    fn classify(raw: &'a [u8]) -> Self {
        let member = raw
            .iter()
            .position(|byte| !is_ows(*byte))
            .and_then(|start| {
                raw.iter()
                    .rposition(|byte| !is_ows(*byte))
                    .map(|end| &raw[start..=end])
            });

        match member {
            None => Self::Empty,
            Some(token) if token.iter().copied().all(is_token_byte) => Self::Token(token),
            Some(_) => Self::Invalid,
        }
    }
}

struct RemovalPlan {
    sorted_names: Vec<String>,
}

impl RemovalPlan {
    fn compile(headers: &HeaderBlock) -> Result<Self> {
        let fixed_names = headers
            .fields
            .iter()
            .filter_map(|field| rule_for(&field.name).map(|rule| rule.name.to_owned()));

        let nominated_names = headers
            .fields
            .iter()
            .enumerate()
            .filter(|(_, field)| {
                rule_for(&field.name)
                    .is_some_and(|rule| rule.action == HeaderAction::RemoveAndNominate)
            })
            .flat_map(|(index, field)| {
                field
                    .value
                    .split(|byte| *byte == b',')
                    .map(move |raw| (index, ConnectionMember::classify(raw)))
            })
            .map(|(index, member)| match member {
                ConnectionMember::Token(token) => Ok(lowercase_ascii(token)),
                ConnectionMember::Empty | ConnectionMember::Invalid => {
                    Err(invalid_connection_token(index))
                }
            });

        let mut sorted_names = fixed_names
            .map(Ok)
            .chain(nominated_names)
            .collect::<Result<Vec<_>>>()?;
        sorted_names.sort_unstable();
        sorted_names.dedup();

        Ok(Self { sorted_names })
    }

    fn removes(&self, name: &str) -> bool {
        self.sorted_names
            .binary_search_by(|candidate| candidate.as_str().cmp(name))
            .is_ok()
    }
}

/// Compile all fixed and `Connection`-nominated names into a sorted removal
/// plan, then retain end-to-end headers without changing their representation.
pub(crate) fn remove_hop_by_hop_headers(headers: &HeaderBlock) -> Result<SanitizedHeaders> {
    let plan = RemovalPlan::compile(headers)?;
    let fields = headers
        .fields
        .iter()
        .filter(|field| !plan.removes(&field.name))
        .cloned()
        .collect();

    Ok(SanitizedHeaders {
        fields,
        removed_names: plan.sorted_names,
    })
}

fn rule_for(name: &str) -> Option<HeaderRule> {
    HEADER_RULES.iter().copied().find(|rule| rule.name == name)
}

fn lowercase_ascii(token: &[u8]) -> String {
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
