use std::ops::Range;

use crate::{HeaderBlock, HeaderField, PolyguardError, Result};

const SECTION_MAX: usize = 32_768;
const FIELD_MAX: usize = 128;
const NAME_MAX: usize = 128;
const VALUE_MAX: usize = 8_192;

#[derive(Clone, Copy)]
enum BoundaryState {
    LineStart { offset: usize },
    LineBody { offset: usize },
}

#[derive(Clone, Copy)]
enum NameClass {
    Token,
    ContainsWhitespace,
    Invalid,
}

enum LexState {
    LineStart,
    Name {
        line_start: usize,
        name_start: usize,
        class: NameClass,
    },
    Value {
        line_start: usize,
        name: Range<usize>,
        value_start: Option<usize>,
        value_end: usize,
    },
}

struct FieldPlan {
    name: Range<usize>,
    value: Range<usize>,
}

struct ValidatedSection {
    fields: Vec<FieldPlan>,
    bytes_consumed: usize,
}

pub(crate) fn parse_header_section(input: &[u8]) -> Result<HeaderBlock> {
    let bytes_consumed = prove_section_boundary(input)?;
    let validated = validate_field_grammar(input, bytes_consumed)?;
    Ok(materialize(input, validated))
}

/// Prove that the complete field section is present before doing any proportional allocation.
fn prove_section_boundary(input: &[u8]) -> Result<usize> {
    let mut state = BoundaryState::LineStart { offset: 0 };
    let mut cursor = 0;

    while cursor < input.len() {
        if cursor == SECTION_MAX {
            return Err(limit_error(
                "header_section_bytes",
                SECTION_MAX,
                SECTION_MAX + 1,
            ));
        }

        let line_start = match state {
            BoundaryState::LineStart { offset } | BoundaryState::LineBody { offset } => offset,
        };

        match input[cursor] {
            b'\n' => return Err(header_error(line_start, "bare_line_ending")),
            b'\r' => {
                if input.get(cursor + 1) != Some(&b'\n') {
                    return Err(header_error(line_start, "bare_line_ending"));
                }

                let next = cursor + 2;
                if next > SECTION_MAX {
                    return Err(limit_error("header_section_bytes", SECTION_MAX, next));
                }
                if matches!(state, BoundaryState::LineStart { .. }) {
                    return Ok(next);
                }

                state = BoundaryState::LineStart { offset: next };
                cursor = next;
            }
            _ => {
                state = BoundaryState::LineBody { offset: line_start };
                cursor += 1;
            }
        }
    }

    Err(PolyguardError::Incomplete)
}

/// Convert the bounded section into immutable spans using an explicit lexical state machine.
fn validate_field_grammar(input: &[u8], bytes_consumed: usize) -> Result<ValidatedSection> {
    let fields_end = bytes_consumed - 2;
    let mut plans = Vec::with_capacity(FIELD_MAX);
    let mut state = LexState::LineStart;
    let mut cursor = 0;

    while cursor < fields_end {
        state = match state {
            LexState::LineStart => {
                if plans.len() == FIELD_MAX {
                    return Err(PolyguardError::TooManyHeaders);
                }
                if matches!(input[cursor], b' ' | b'\t') {
                    return Err(header_error(cursor, "obs_fold"));
                }

                let class = classify_name_byte(input[cursor]);
                let line_start = cursor;
                cursor += 1;
                LexState::Name {
                    line_start,
                    name_start: line_start,
                    class,
                }
            }
            LexState::Name {
                line_start,
                name_start,
                class,
            } => match input[cursor] {
                b':' => {
                    validate_name(name_start, cursor, class, line_start)?;
                    cursor += 1;
                    LexState::Value {
                        line_start,
                        name: name_start..cursor - 1,
                        value_start: None,
                        value_end: cursor,
                    }
                }
                b'\r' => return Err(header_error(line_start, "invalid_name")),
                byte => {
                    cursor += 1;
                    LexState::Name {
                        line_start,
                        name_start,
                        class: advance_name_class(class, byte),
                    }
                }
            },
            LexState::Value {
                line_start,
                name,
                value_start,
                value_end,
            } => {
                let byte = input[cursor];
                if byte == b'\r' {
                    let start = value_start.unwrap_or(cursor);
                    let end = value_start.map_or(cursor, |_| value_end);
                    let trimmed_length = end - start;
                    if trimmed_length > VALUE_MAX {
                        return Err(limit_error("header_value_bytes", VALUE_MAX, trimmed_length));
                    }
                    plans.push(FieldPlan {
                        name,
                        value: start..end,
                    });
                    cursor += 2;
                    LexState::LineStart
                } else {
                    if !is_value_byte(byte) {
                        return Err(header_error(line_start, "invalid_value_byte"));
                    }
                    let is_content = !matches!(byte, b' ' | b'\t');
                    let next_start = value_start.or(is_content.then_some(cursor));
                    let next_end = if is_content { cursor + 1 } else { value_end };
                    cursor += 1;
                    LexState::Value {
                        line_start,
                        name,
                        value_start: next_start,
                        value_end: next_end,
                    }
                }
            }
        };
    }

    debug_assert!(matches!(state, LexState::LineStart));
    Ok(ValidatedSection {
        fields: plans,
        bytes_consumed,
    })
}

fn validate_name(
    name_start: usize,
    name_end: usize,
    class: NameClass,
    line_start: usize,
) -> Result<()> {
    let length = name_end - name_start;
    if length > NAME_MAX {
        return Err(limit_error("header_name_bytes", NAME_MAX, length));
    }
    match class {
        NameClass::Token => Ok(()),
        NameClass::ContainsWhitespace => Err(header_error(line_start, "whitespace_before_colon")),
        NameClass::Invalid => Err(header_error(line_start, "invalid_name")),
    }
}

fn materialize(input: &[u8], section: ValidatedSection) -> HeaderBlock {
    let fields = section
        .fields
        .into_iter()
        .map(|plan| HeaderField {
            name: input[plan.name]
                .iter()
                .map(|byte| char::from(byte.to_ascii_lowercase()))
                .collect(),
            value: input[plan.value].to_vec(),
        })
        .collect();

    HeaderBlock {
        fields,
        bytes_consumed: section.bytes_consumed,
    }
}

fn classify_name_byte(byte: u8) -> NameClass {
    if is_token(byte) {
        NameClass::Token
    } else if matches!(byte, b' ' | b'\t') {
        NameClass::ContainsWhitespace
    } else {
        NameClass::Invalid
    }
}

fn advance_name_class(class: NameClass, byte: u8) -> NameClass {
    match (class, classify_name_byte(byte)) {
        (NameClass::ContainsWhitespace, _) | (_, NameClass::ContainsWhitespace) => {
            NameClass::ContainsWhitespace
        }
        (NameClass::Invalid, _) | (_, NameClass::Invalid) => NameClass::Invalid,
        _ => NameClass::Token,
    }
}

fn is_token(byte: u8) -> bool {
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

fn is_value_byte(byte: u8) -> bool {
    byte == b'\t' || (b' '..=b'~').contains(&byte) || byte >= 0x80
}

fn header_error(index: usize, reason: &str) -> PolyguardError {
    PolyguardError::InvalidHeader {
        index,
        reason: reason.into(),
    }
}

fn limit_error(limit: &str, max: usize, actual: usize) -> PolyguardError {
    PolyguardError::LimitExceeded {
        limit: limit.into(),
        max,
        actual,
    }
}
