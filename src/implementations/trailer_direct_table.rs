use crate::{HeaderField, PolyguardError, Result, TrailerBlock};

const TRAILER_BYTES_MAX: usize = 8_192;
const TRAILER_FIELDS_MAX: usize = 32;
const FIELD_NAME_MAX: usize = 128;
const FIELD_VALUE_MAX: usize = 8_192;

#[derive(Clone, Copy)]
enum ByteKind {
    Colon,
    OptionalWhitespace,
    Token,
    ValueOnly,
    Prohibited,
}

#[derive(Clone, Copy)]
struct FieldSpan {
    name_end: usize,
    value_start: usize,
    value_end: usize,
}

#[derive(Clone, Copy)]
struct LineSummary {
    starts_with_whitespace: bool,
    colon: Option<usize>,
    whitespace_in_name: bool,
    invalid_name: bool,
    invalid_value: bool,
    value_start: Option<usize>,
    value_end: usize,
}

enum LineVerdict {
    Field(FieldSpan),
    Invalid(&'static str),
}

struct DeclarationTable<'a> {
    sorted: Vec<&'a str>,
}

impl<'a> DeclarationTable<'a> {
    fn new(names: &'a [String]) -> Result<Self> {
        for name in names {
            let valid = !name.is_empty()
                && name.len() <= FIELD_NAME_MAX
                && name.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || is_token_punctuation(byte)
                });
            if !valid {
                return Err(invalid_trailer("invalid_declaration"));
            }
            if is_forbidden(name) {
                return Err(invalid_trailer("forbidden_field"));
            }
        }

        let sorted = radix_order(names.iter().map(String::as_str).collect());
        if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid_trailer("duplicate_declaration"));
        }
        Ok(Self { sorted })
    }

    fn contains(&self, name: &str) -> bool {
        self.sorted.contains(&name)
    }
}

fn radix_order(mut names: Vec<&str>) -> Vec<&str> {
    const BUCKETS: usize = 257;

    let mut scratch = vec![""; names.len()];
    for position in (0..FIELD_NAME_MAX).rev() {
        let mut counts = [0usize; BUCKETS];
        for name in &names {
            counts[radix_bucket(name, position)] += 1;
        }

        let mut next = [0usize; BUCKETS];
        let mut running_total = 0;
        for bucket in 0..BUCKETS {
            next[bucket] = running_total;
            running_total += counts[bucket];
        }
        for name in &names {
            let bucket = radix_bucket(name, position);
            scratch[next[bucket]] = name;
            next[bucket] += 1;
        }
        std::mem::swap(&mut names, &mut scratch);
    }
    names
}

fn radix_bucket(name: &str, position: usize) -> usize {
    name.as_bytes()
        .get(position)
        .map_or(0, |byte| usize::from(*byte) + 1)
}

pub(crate) fn parse_trailer_section(
    input: &[u8],
    declared_names: &[String],
) -> Result<TrailerBlock> {
    let declarations = DeclarationTable::new(declared_names)?;
    let mut fields: Vec<HeaderField> = Vec::new();
    let mut cursor = 0;

    loop {
        let (line_end, next_line) = locate_line_end(input, cursor)?;
        if line_end == cursor {
            return Ok(TrailerBlock {
                fields,
                bytes_consumed: next_line,
            });
        }
        if fields.len() == TRAILER_FIELDS_MAX {
            return Err(invalid_trailer("too_many_fields"));
        }

        let span = match summarize_and_decide(input, cursor, line_end) {
            LineVerdict::Field(span) => span,
            LineVerdict::Invalid(reason) => return Err(invalid_trailer(reason)),
        };

        let name = ascii_lowercase(&input[cursor..span.name_end]);
        if is_forbidden(&name) {
            return Err(invalid_trailer("forbidden_field"));
        }
        if !declarations.contains(&name) {
            return Err(invalid_trailer("undeclared_field"));
        }
        if fields.iter().any(|field| field.name == name) {
            return Err(invalid_trailer("duplicate_field"));
        }

        fields.push(HeaderField {
            name,
            value: input[span.value_start..span.value_end].to_vec(),
        });
        cursor = next_line;
    }
}

fn locate_line_end(input: &[u8], start: usize) -> Result<(usize, usize)> {
    let mut position = start;
    loop {
        if position == TRAILER_BYTES_MAX {
            return if position == input.len() {
                Err(PolyguardError::Incomplete)
            } else {
                Err(trailer_byte_limit(TRAILER_BYTES_MAX + 1))
            };
        }

        match input.get(position).copied() {
            None => return Err(PolyguardError::Incomplete),
            Some(b'\n') => return Err(invalid_trailer("bare_line_ending")),
            Some(b'\r') => {
                if input.get(position + 1) != Some(&b'\n') {
                    return Err(invalid_trailer("bare_line_ending"));
                }
                let after_crlf = position + 2;
                if after_crlf > TRAILER_BYTES_MAX {
                    return Err(trailer_byte_limit(after_crlf));
                }
                return Ok((position, after_crlf));
            }
            Some(_) => position += 1,
        }
    }
}

fn summarize_and_decide(input: &[u8], start: usize, end: usize) -> LineVerdict {
    let mut summary = LineSummary {
        starts_with_whitespace: matches!(input[start], b' ' | b'\t'),
        colon: None,
        whitespace_in_name: false,
        invalid_name: false,
        invalid_value: false,
        value_start: None,
        value_end: end,
    };

    for (offset, byte) in input[start..end].iter().copied().enumerate() {
        let position = start + offset;
        let kind = classify(byte);
        if summary.colon.is_none() {
            match kind {
                ByteKind::Colon => summary.colon = Some(position),
                ByteKind::OptionalWhitespace => summary.whitespace_in_name = true,
                ByteKind::Token => {}
                ByteKind::ValueOnly | ByteKind::Prohibited => summary.invalid_name = true,
            }
        } else {
            match kind {
                ByteKind::Prohibited => summary.invalid_value = true,
                ByteKind::OptionalWhitespace if summary.value_start.is_none() => {}
                ByteKind::OptionalWhitespace => {}
                ByteKind::Colon | ByteKind::Token | ByteKind::ValueOnly => {
                    summary.value_start.get_or_insert(position);
                    summary.value_end = position + 1;
                }
            }
        }
    }

    let name_length = summary.colon.map_or(0, |colon| colon - start);
    let value_start = summary.value_start.unwrap_or(end);
    let value_length = summary.value_end - value_start;

    // This table is the single precedence point for wire-field grammar decisions.
    match (
        summary.starts_with_whitespace,
        summary.colon,
        name_length,
        summary.whitespace_in_name,
        summary.invalid_name,
        summary.invalid_value,
        value_length,
    ) {
        (true, _, _, _, _, _, _) => LineVerdict::Invalid("obs_fold"),
        (_, None, _, _, _, _, _) | (_, _, 0, _, _, _, _) => LineVerdict::Invalid("invalid_name"),
        (_, _, length, _, _, _, _) if length > FIELD_NAME_MAX => {
            LineVerdict::Invalid("name_too_long")
        }
        (_, _, _, true, _, _, _) => LineVerdict::Invalid("whitespace_before_colon"),
        (_, _, _, _, true, _, _) => LineVerdict::Invalid("invalid_name"),
        (_, _, _, _, _, true, _) => LineVerdict::Invalid("invalid_value_byte"),
        (_, _, _, _, _, _, length) if length > FIELD_VALUE_MAX => {
            LineVerdict::Invalid("value_too_long")
        }
        (_, Some(name_end), _, _, _, _, _) => LineVerdict::Field(FieldSpan {
            name_end,
            value_start,
            value_end: summary.value_end,
        }),
    }
}

fn classify(byte: u8) -> ByteKind {
    match byte {
        b':' => ByteKind::Colon,
        b' ' | b'\t' => ByteKind::OptionalWhitespace,
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => ByteKind::Token,
        byte if is_token_punctuation(byte) => ByteKind::Token,
        0x21..=0x7e | 0x80..=0xff => ByteKind::ValueOnly,
        _ => ByteKind::Prohibited,
    }
}

fn is_token_punctuation(byte: u8) -> bool {
    matches!(
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

fn is_forbidden(name: &str) -> bool {
    name.starts_with("x-forwarded-")
        || matches!(
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
        )
}

fn ascii_lowercase(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect()
}

fn invalid_trailer(reason: &str) -> PolyguardError {
    PolyguardError::InvalidTrailer {
        reason: reason.into(),
    }
}

fn trailer_byte_limit(actual: usize) -> PolyguardError {
    PolyguardError::LimitExceeded {
        limit: "trailer_bytes".into(),
        max: TRAILER_BYTES_MAX,
        actual,
    }
}
