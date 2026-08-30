use std::cmp::Ordering;

use crate::{HeaderField, PolyguardError, Result, TrailerBlock};

const MAX_TRAILER_BYTES: usize = 8_192;
const MAX_TRAILER_FIELDS: usize = 32;
const MAX_FIELD_NAME_BYTES: usize = 128;

/// A section whose terminating empty line and byte limit have been established.
struct BoundedSection<'a> {
    field_lines: &'a [u8],
    bytes_consumed: usize,
}

/// A declaration collection containing only unique, permitted lowercase tokens.
struct DeclarationDomain<'a> {
    names: Vec<&'a str>,
}

/// A syntactically valid wire name. Its canonical spelling is computed only for output.
#[derive(Clone, Copy)]
struct WireName<'a>(&'a [u8]);

/// A field value with valid octets and optional whitespace removed from both ends.
#[derive(Clone, Copy)]
struct WireValue<'a>(&'a [u8]);

#[derive(Clone, Copy)]
struct PermittedField<'a> {
    name: WireName<'a>,
    value: WireValue<'a>,
}

pub(crate) fn parse_trailer_section(
    input: &[u8],
    declared_names: &[String],
) -> Result<TrailerBlock> {
    let section = establish_section_boundary(input)?;
    let declarations = DeclarationDomain::validate(declared_names)?;
    let fields = validate_and_permit_fields(section.field_lines, &declarations)?;

    Ok(build_trailer_block(fields, section.bytes_consumed))
}

fn establish_section_boundary(input: &[u8]) -> Result<BoundedSection<'_>> {
    // One byte past the bound is enough to prove an over-limit section. Restricting the
    // iterator up front also prevents a long unterminated input from being scanned in full.
    let observable = &input[..input.len().min(MAX_TRAILER_BYTES + 1)];
    let mut line_start = 0usize;

    for segment in observable.split_inclusive(|byte| *byte == b'\n') {
        let ends_in_lf = segment.last() == Some(&b'\n');
        if !ends_in_lf {
            if segment
                .iter()
                .take(MAX_TRAILER_BYTES.saturating_sub(line_start))
                .any(|byte| *byte == b'\r')
            {
                return Err(invalid("bare_line_ending"));
            }
            break;
        }

        let segment_end = line_start + segment.len();
        let earlier_cr = segment[..segment.len() - 1]
            .iter()
            .enumerate()
            .find(|(offset, byte)| **byte == b'\r' && line_start + *offset + 1 < segment_end - 1)
            .map(|(offset, _)| line_start + offset);
        if earlier_cr.is_some_and(|position| position < MAX_TRAILER_BYTES) {
            return Err(invalid("bare_line_ending"));
        }
        if segment_end > MAX_TRAILER_BYTES {
            return Err(trailer_limit());
        }
        if segment.get(segment.len().wrapping_sub(2)) != Some(&b'\r') {
            return Err(invalid("bare_line_ending"));
        }

        if segment.len() == 2 {
            return Ok(BoundedSection {
                field_lines: &input[..line_start],
                bytes_consumed: segment_end,
            });
        }
        line_start = segment_end;
    }

    if input.len() > MAX_TRAILER_BYTES {
        return Err(trailer_limit());
    }
    Err(PolyguardError::Incomplete)
}

impl<'a> DeclarationDomain<'a> {
    fn validate(declared_names: &'a [String]) -> Result<Self> {
        let mut names = Vec::with_capacity(declared_names.len());

        for name in declared_names {
            if name.is_empty()
                || name.len() > MAX_FIELD_NAME_BYTES
                || !name.bytes().all(is_lowercase_token_byte)
            {
                return Err(invalid("invalid_declaration"));
            }
            if is_forbidden(name) {
                return Err(invalid("forbidden_field"));
            }
            names.push(name.as_str());
        }

        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("duplicate_declaration"));
        }
        Ok(Self { names })
    }

    fn contains(&self, candidate: WireName<'_>) -> bool {
        self.names
            .binary_search_by(|declared| {
                compare_canonical(candidate.0, declared.as_bytes()).reverse()
            })
            .is_ok()
    }
}

fn validate_and_permit_fields<'a>(
    field_lines: &'a [u8],
    declarations: &DeclarationDomain<'_>,
) -> Result<Vec<PermittedField<'a>>> {
    let mut permitted = Vec::new();
    let mut lines = field_lines.split(|byte| *byte == b'\n');
    let trailing_empty = lines.next_back();
    debug_assert_eq!(trailing_empty, Some(&[][..]));

    for terminated_line in lines {
        if permitted.len() == MAX_TRAILER_FIELDS {
            return Err(invalid("too_many_fields"));
        }

        let line = &terminated_line[..terminated_line.len() - 1];
        let field = validate_field_grammar(line)?;
        authorize_field(field.name, declarations, &permitted)?;
        permitted.push(field);
    }

    Ok(permitted)
}

fn validate_field_grammar(line: &[u8]) -> Result<PermittedField<'_>> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(invalid("obs_fold"));
    }

    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return Err(invalid("invalid_name"));
    };
    let name = &line[..colon];
    if name.is_empty() || name.len() > MAX_FIELD_NAME_BYTES {
        return Err(invalid("invalid_name"));
    }
    if name.iter().any(|byte| matches!(byte, b' ' | b'\t')) {
        return Err(invalid("whitespace_before_colon"));
    }
    if !name.iter().copied().all(is_token_byte) {
        return Err(invalid("invalid_name"));
    }

    let untrimmed = &line[colon + 1..];
    if !untrimmed.iter().copied().all(is_field_value_byte) {
        return Err(invalid("invalid_value_byte"));
    }
    let leading = untrimmed.iter().take_while(|byte| is_ows(**byte)).count();
    let trailing = untrimmed
        .iter()
        .rev()
        .take_while(|byte| is_ows(**byte))
        .count();
    let value_end = untrimmed.len().saturating_sub(trailing).max(leading);

    Ok(PermittedField {
        name: WireName(name),
        value: WireValue(&untrimmed[leading..value_end]),
    })
}

fn authorize_field(
    name: WireName<'_>,
    declarations: &DeclarationDomain<'_>,
    accepted: &[PermittedField<'_>],
) -> Result<()> {
    if is_forbidden_wire_name(name.0) {
        return Err(invalid("forbidden_field"));
    }
    if !declarations.contains(name) {
        return Err(invalid("undeclared_field"));
    }
    if accepted
        .iter()
        .any(|field| field.name.0.eq_ignore_ascii_case(name.0))
    {
        return Err(invalid("duplicate_field"));
    }
    Ok(())
}

fn build_trailer_block(fields: Vec<PermittedField<'_>>, bytes_consumed: usize) -> TrailerBlock {
    TrailerBlock {
        fields: fields
            .into_iter()
            .map(|field| HeaderField {
                name: field
                    .name
                    .0
                    .iter()
                    .map(|byte| char::from(byte.to_ascii_lowercase()))
                    .collect(),
                value: field.value.0.to_vec(),
            })
            .collect(),
        bytes_consumed,
    }
}

fn compare_canonical(wire: &[u8], declared: &[u8]) -> Ordering {
    wire.iter()
        .map(u8::to_ascii_lowercase)
        .cmp(declared.iter().copied())
}

fn is_lowercase_token_byte(byte: u8) -> bool {
    !byte.is_ascii_uppercase() && is_token_byte(byte)
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

fn is_ows(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn is_forbidden_wire_name(name: &[u8]) -> bool {
    const FORBIDDEN: [&[u8]; 13] = [
        b"content-length",
        b"transfer-encoding",
        b"host",
        b"connection",
        b"trailer",
        b"upgrade",
        b"forwarded",
        b"authorization",
        b"proxy-authorization",
        b"cookie",
        b"set-cookie",
        b"x-forwarded-for",
        b"x-forwarded-proto",
    ];

    name.len() >= b"x-forwarded-".len()
        && name[..b"x-forwarded-".len()].eq_ignore_ascii_case(b"x-forwarded-")
        || FORBIDDEN
            .iter()
            .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
}

fn is_forbidden(name: &str) -> bool {
    is_forbidden_wire_name(name.as_bytes())
}

fn invalid(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidTrailer {
        reason: reason.into(),
    }
}

fn trailer_limit() -> PolyguardError {
    PolyguardError::LimitExceeded {
        limit: "trailer_bytes".into(),
        max: MAX_TRAILER_BYTES,
        actual: MAX_TRAILER_BYTES + 1,
    }
}
