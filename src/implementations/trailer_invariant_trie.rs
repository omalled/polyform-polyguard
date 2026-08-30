use crate::{HeaderField, PolyguardError, Result, TrailerBlock};

const TRAILER_BYTES: usize = 8_192;
const TRAILER_FIELDS: usize = 32;
const HEADER_NAME_BYTES: usize = 128;

#[derive(Clone, Copy)]
struct FramedSection<'a> {
    field_bytes: &'a [u8],
    bytes_consumed: usize,
}

#[derive(Clone, Copy)]
struct RawField<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

struct TrailerName(String);

struct TrailerValue<'a>(&'a [u8]);

struct ValidatedField<'a> {
    name: TrailerName,
    value: TrailerValue<'a>,
}

#[derive(Default)]
struct NameNode {
    edges: Vec<(u8, usize)>,
    declared: bool,
    received: bool,
}

struct DeclaredNames {
    nodes: Vec<NameNode>,
}

pub(crate) fn parse_trailer_section(
    input: &[u8],
    declared_names: &[String],
) -> Result<TrailerBlock> {
    let framed = frame_section(input)?;
    let mut declarations = DeclaredNames::validate(declared_names)?;
    let validated = validate_fields(framed.field_bytes, &mut declarations)?;
    Ok(construct_output(validated, framed.bytes_consumed))
}

fn frame_section(input: &[u8]) -> Result<FramedSection<'_>> {
    let mut line_start = 0;
    let mut position = 0;

    while position < input.len() {
        if position == TRAILER_BYTES {
            return Err(limit_exceeded(TRAILER_BYTES + 1));
        }

        let byte = input[position];
        if byte == b'\n' {
            return Err(invalid_trailer("bare_line_ending"));
        }
        if byte != b'\r' {
            position += 1;
            continue;
        }
        if input.get(position + 1) != Some(&b'\n') {
            return Err(invalid_trailer("bare_line_ending"));
        }

        let after_line = position + 2;
        if after_line > TRAILER_BYTES {
            return Err(limit_exceeded(after_line));
        }
        if position == line_start {
            return Ok(FramedSection {
                field_bytes: &input[..position],
                bytes_consumed: after_line,
            });
        }

        line_start = after_line;
        position = after_line;
    }

    Err(PolyguardError::Incomplete)
}

impl DeclaredNames {
    fn validate(names: &[String]) -> Result<Self> {
        let mut declarations = Self {
            nodes: vec![NameNode::default()],
        };

        for name in names {
            if !is_lowercase_token(name.as_bytes()) {
                return Err(invalid_trailer("invalid_declaration"));
            }
            if is_forbidden(name) {
                return Err(invalid_trailer("forbidden_field"));
            }
            declarations.insert(name.as_bytes())?;
        }

        Ok(declarations)
    }

    fn insert(&mut self, name: &[u8]) -> Result<()> {
        let mut node_index = 0;
        for byte in name {
            let next = self.nodes[node_index]
                .edges
                .iter()
                .find(|(label, _)| label == byte)
                .map(|(_, child)| *child);
            node_index = match next {
                Some(child) => child,
                None => {
                    let child = self.nodes.len();
                    self.nodes.push(NameNode::default());
                    self.nodes[node_index].edges.push((*byte, child));
                    child
                }
            };
        }

        if self.nodes[node_index].declared {
            return Err(invalid_trailer("duplicate_declaration"));
        }
        self.nodes[node_index].declared = true;
        Ok(())
    }

    fn accept_received(&mut self, name: &str) -> Result<()> {
        if is_forbidden(name) {
            return Err(invalid_trailer("forbidden_field"));
        }

        let mut node_index = 0;
        for byte in name.bytes() {
            let Some(child) = self.nodes[node_index]
                .edges
                .iter()
                .find(|(label, _)| *label == byte)
                .map(|(_, child)| *child)
            else {
                return Err(invalid_trailer("undeclared_field"));
            };
            node_index = child;
        }

        if !self.nodes[node_index].declared {
            return Err(invalid_trailer("undeclared_field"));
        }
        if self.nodes[node_index].received {
            return Err(invalid_trailer("duplicate_field"));
        }
        self.nodes[node_index].received = true;
        Ok(())
    }
}

fn validate_fields<'a>(
    bytes: &'a [u8],
    declarations: &mut DeclaredNames,
) -> Result<Vec<ValidatedField<'a>>> {
    let mut fields = Vec::new();
    let mut remaining = bytes;

    while !remaining.is_empty() {
        if fields.len() == TRAILER_FIELDS {
            return Err(invalid_trailer("too_many_fields"));
        }

        let line_end = remaining
            .iter()
            .position(|byte| *byte == b'\r')
            .expect("framing established a CRLF after every trailer field");
        let raw = validate_line(&remaining[..line_end])?;
        let name = TrailerName::canonicalize(raw.name);
        declarations.accept_received(&name.0)?;
        fields.push(ValidatedField {
            name,
            value: TrailerValue::trim(raw.value),
        });
        remaining = &remaining[line_end + 2..];
    }

    Ok(fields)
}

fn validate_line(line: &[u8]) -> Result<RawField<'_>> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(invalid_trailer("obs_fold"));
    }

    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return Err(invalid_trailer("invalid_name"));
    };
    let name = &line[..colon];
    if name.is_empty() || name.len() > HEADER_NAME_BYTES {
        return Err(invalid_trailer("invalid_name"));
    }
    if name.iter().any(|byte| matches!(byte, b' ' | b'\t')) {
        return Err(invalid_trailer("whitespace_before_colon"));
    }
    if !name.iter().copied().all(is_token_byte) {
        return Err(invalid_trailer("invalid_name"));
    }

    let value = &line[colon + 1..];
    if !value.iter().copied().all(is_field_value_byte) {
        return Err(invalid_trailer("invalid_value_byte"));
    }

    Ok(RawField { name, value })
}

impl TrailerName {
    fn canonicalize(bytes: &[u8]) -> Self {
        Self(
            bytes
                .iter()
                .map(|byte| char::from(byte.to_ascii_lowercase()))
                .collect(),
        )
    }
}

impl TrailerValue<'_> {
    fn trim(bytes: &[u8]) -> TrailerValue<'_> {
        let first = bytes
            .iter()
            .position(|byte| !matches!(byte, b' ' | b'\t'))
            .unwrap_or(bytes.len());
        let last = bytes
            .iter()
            .rposition(|byte| !matches!(byte, b' ' | b'\t'))
            .map_or(first, |index| index + 1);
        TrailerValue(&bytes[first..last])
    }
}

fn construct_output(fields: Vec<ValidatedField<'_>>, bytes_consumed: usize) -> TrailerBlock {
    TrailerBlock {
        fields: fields
            .into_iter()
            .map(|field| HeaderField {
                name: field.name.0,
                value: field.value.0.to_vec(),
            })
            .collect(),
        bytes_consumed,
    }
}

fn is_lowercase_token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().copied().all(is_token_byte)
        && bytes
            .iter()
            .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_lowercase())
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

fn is_field_value_byte(byte: u8) -> bool {
    byte == b'\t' || (b' '..=b'~').contains(&byte) || byte >= 0x80
}

fn is_forbidden(name: &str) -> bool {
    matches!(
        name,
        "content-length"
            | "transfer-encoding"
            | "host"
            | "connection"
            | "trailer"
            | "upgrade"
            | "forwarded"
            | "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
    ) || name.starts_with("x-forwarded-")
}

fn invalid_trailer(reason: &str) -> PolyguardError {
    PolyguardError::InvalidTrailer {
        reason: reason.into(),
    }
}

fn limit_exceeded(actual: usize) -> PolyguardError {
    PolyguardError::LimitExceeded {
        limit: "trailer_bytes".into(),
        max: TRAILER_BYTES,
        actual,
    }
}
