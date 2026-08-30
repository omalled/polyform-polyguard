use crate::{HeaderBlock, PolyguardError, Result, SanitizedHeaders};

const CONNECTION: &str = "connection";
const INVALID_CONNECTION_TOKEN: &str = "invalid_connection_token";
const FIXED_HOP_BY_HOP: [&str; 9] = [
    CONNECTION,
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

#[derive(Default)]
struct TrieNode {
    terminal: bool,
    children: Vec<(u8, usize)>,
}

struct TokenTrie {
    nodes: Vec<TrieNode>,
}

impl TokenTrie {
    fn new() -> Self {
        Self {
            nodes: vec![TrieNode::default()],
        }
    }

    fn insert(&mut self, token: &[u8]) -> bool {
        let mut node_index = 0;
        for &byte in token {
            let child = self.nodes[node_index]
                .children
                .iter()
                .find_map(|&(edge, index)| (edge == byte).then_some(index));
            node_index = match child {
                Some(index) => index,
                None => {
                    let index = self.nodes.len();
                    self.nodes.push(TrieNode::default());
                    self.nodes[node_index].children.push((byte, index));
                    index
                }
            };
        }

        if self.nodes[node_index].terminal {
            return false;
        }
        self.nodes[node_index].terminal = true;
        true
    }

    fn contains(&self, token: &[u8]) -> bool {
        let mut node_index = 0;
        for &byte in token {
            let Some(index) = self.nodes[node_index]
                .children
                .iter()
                .find_map(|&(edge, index)| (edge == byte).then_some(index))
            else {
                return false;
            };
            node_index = index;
        }
        self.nodes[node_index].terminal
    }
}

fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while matches!(bytes.first(), Some(b' ' | b'\t')) {
        bytes = &bytes[1..];
    }
    while matches!(bytes.last(), Some(b' ' | b'\t')) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
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
        reason: INVALID_CONNECTION_TOKEN.into(),
    }
}

fn collect_nominations(headers: &HeaderBlock) -> Result<(TokenTrie, Vec<String>)> {
    let mut names = TokenTrie::new();
    let mut unique_names = Vec::new();

    for (index, field) in headers.fields.iter().enumerate() {
        if field.name != CONNECTION {
            continue;
        }
        for member in field.value.split(|byte| *byte == b',') {
            let member = trim_ows(member);
            if member.is_empty() || !member.iter().copied().all(is_token_byte) {
                return Err(invalid_connection_token(index));
            }

            let lowercase: Vec<u8> = member.iter().map(u8::to_ascii_lowercase).collect();
            let name = String::from_utf8(lowercase).map_err(|_| invalid_connection_token(index))?;
            if names.insert(name.as_bytes()) {
                unique_names.push(name);
            }
        }
    }

    Ok((names, unique_names))
}

fn is_fixed(name: &str) -> bool {
    FIXED_HOP_BY_HOP.contains(&name)
}

pub fn remove_hop_by_hop_headers(headers: &HeaderBlock) -> Result<SanitizedHeaders> {
    let (nominations, mut removed_names) = collect_nominations(headers)?;
    let mut fields = Vec::with_capacity(headers.fields.len());

    for field in &headers.fields {
        let fixed = is_fixed(&field.name);
        let nominated = nominations.contains(field.name.as_bytes());
        if !fixed && !nominated {
            fields.push(field.clone());
            continue;
        }
        if fixed {
            removed_names.push(field.name.clone());
        }
    }

    removed_names.sort_unstable();
    removed_names.dedup();
    Ok(SanitizedHeaders {
        fields,
        removed_names,
    })
}
