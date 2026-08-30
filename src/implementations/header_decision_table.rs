use crate::{HeaderBlock, HeaderField, PolyguardError, Result};

const SECTION_BYTES_MAX: usize = 32_768;
const FIELD_COUNT_MAX: usize = 128;
const NAME_BYTES_MAX: usize = 128;
const VALUE_BYTES_MAX: usize = 8_192;

#[derive(Clone, Copy)]
struct FieldLayout {
    name_start: usize,
    name_end: usize,
    value_start: usize,
    value_end: usize,
}

impl FieldLayout {
    const EMPTY: Self = Self {
        name_start: 0,
        name_end: 0,
        value_start: 0,
        value_end: 0,
    };
}

#[derive(Clone, Copy)]
enum FieldPart {
    Name,
    Value,
}

#[derive(Clone, Copy)]
enum WireByte {
    Colon,
    Ows,
    Token,
    ValueOnly,
    Forbidden,
}

#[derive(Clone, Copy)]
struct LineFacts {
    colon: Option<usize>,
    name_has_whitespace: bool,
    name_has_invalid_byte: bool,
    value_has_invalid_byte: bool,
    first_value_content: Option<usize>,
    last_value_content: usize,
}

enum LineDecision {
    Accept(FieldLayout),
    Reject(&'static str),
    NameLimit(usize),
    ValueLimit(usize),
}

struct ValidatedFields {
    layouts: [FieldLayout; FIELD_COUNT_MAX],
    count: usize,
    bytes_consumed: usize,
}

pub(crate) fn parse_header_section(input: &[u8]) -> Result<HeaderBlock> {
    let validated = validate_section(input)?;
    Ok(build_header_block(input, validated))
}

fn validate_section(input: &[u8]) -> Result<ValidatedFields> {
    let mut layouts = [FieldLayout::EMPTY; FIELD_COUNT_MAX];
    let mut count = 0;
    let mut line_start = 0;

    loop {
        let (line_end, next_line) = find_crlf(input, line_start)?;
        if line_end == line_start {
            return Ok(ValidatedFields {
                layouts,
                count,
                bytes_consumed: next_line,
            });
        }
        if count == FIELD_COUNT_MAX {
            return Err(PolyguardError::TooManyHeaders);
        }

        layouts[count] = match decide_line(input, line_start, line_end) {
            LineDecision::Accept(layout) => layout,
            LineDecision::Reject(reason) => return Err(invalid_header(line_start, reason)),
            LineDecision::NameLimit(actual) => {
                return Err(limit_exceeded("header_name_bytes", NAME_BYTES_MAX, actual));
            }
            LineDecision::ValueLimit(actual) => {
                return Err(limit_exceeded(
                    "header_value_bytes",
                    VALUE_BYTES_MAX,
                    actual,
                ));
            }
        };
        count += 1;
        line_start = next_line;
    }
}

fn find_crlf(input: &[u8], line_start: usize) -> Result<(usize, usize)> {
    let mut index = line_start;
    loop {
        if index == SECTION_BYTES_MAX {
            return if index == input.len() {
                Err(PolyguardError::Incomplete)
            } else {
                Err(limit_exceeded(
                    "header_section_bytes",
                    SECTION_BYTES_MAX,
                    SECTION_BYTES_MAX + 1,
                ))
            };
        }

        match input.get(index).copied() {
            None => return Err(PolyguardError::Incomplete),
            Some(b'\n') => return Err(invalid_header(line_start, "bare_line_ending")),
            Some(b'\r') => {
                if input.get(index + 1) != Some(&b'\n') {
                    return Err(invalid_header(line_start, "bare_line_ending"));
                }
                let next = index + 2;
                if next > SECTION_BYTES_MAX {
                    return Err(limit_exceeded(
                        "header_section_bytes",
                        SECTION_BYTES_MAX,
                        next,
                    ));
                }
                return Ok((index, next));
            }
            Some(_) => index += 1,
        }
    }
}

fn decide_line(input: &[u8], start: usize, end: usize) -> LineDecision {
    let begins_with_ows = matches!(input[start], b' ' | b'\t');
    let mut part = FieldPart::Name;
    let mut facts = LineFacts {
        colon: None,
        name_has_whitespace: false,
        name_has_invalid_byte: false,
        value_has_invalid_byte: false,
        first_value_content: None,
        last_value_content: start,
    };

    for (relative, byte) in input[start..end].iter().copied().enumerate() {
        let index = start + relative;
        let class = classify(byte);
        observe_byte(part, class, index, &mut facts);
        if matches!((part, class), (FieldPart::Name, WireByte::Colon)) {
            part = FieldPart::Value;
        }
    }

    let name_length = facts.colon.map_or(0, |colon| colon - start);
    let value_start = facts.first_value_content.unwrap_or(end);
    let value_end = facts
        .first_value_content
        .map_or(end, |_| facts.last_value_content);
    let value_length = value_end - value_start;

    // This table is the sole precedence point for all field-grammar outcomes.
    match (
        begins_with_ows,
        facts.colon,
        name_length,
        facts.name_has_whitespace,
        facts.name_has_invalid_byte,
        facts.value_has_invalid_byte,
        value_length,
    ) {
        (true, _, _, _, _, _, _) => LineDecision::Reject("obs_fold"),
        (_, None, _, _, _, _, _) => LineDecision::Reject("invalid_name"),
        (_, _, 0, _, _, _, _) => LineDecision::Reject("invalid_name"),
        (_, _, length, _, _, _, _) if length > NAME_BYTES_MAX => LineDecision::NameLimit(length),
        (_, _, _, true, _, _, _) => LineDecision::Reject("whitespace_before_colon"),
        (_, _, _, _, true, _, _) => LineDecision::Reject("invalid_name"),
        (_, _, _, _, _, true, _) => LineDecision::Reject("invalid_value_byte"),
        (_, _, _, _, _, _, length) if length > VALUE_BYTES_MAX => LineDecision::ValueLimit(length),
        (_, Some(colon), _, _, _, _, _) => LineDecision::Accept(FieldLayout {
            name_start: start,
            name_end: colon,
            value_start,
            value_end,
        }),
    }
}

fn observe_byte(part: FieldPart, byte: WireByte, index: usize, facts: &mut LineFacts) {
    match (part, byte) {
        (FieldPart::Name, WireByte::Colon) => facts.colon = Some(index),
        (FieldPart::Name, WireByte::Ows) => facts.name_has_whitespace = true,
        (FieldPart::Name, WireByte::Token) => {}
        (FieldPart::Name, WireByte::ValueOnly | WireByte::Forbidden) => {
            facts.name_has_invalid_byte = true;
        }
        (FieldPart::Value, WireByte::Forbidden) => facts.value_has_invalid_byte = true,
        (FieldPart::Value, WireByte::Ows) => {}
        (FieldPart::Value, WireByte::Colon | WireByte::Token | WireByte::ValueOnly) => {
            facts.first_value_content.get_or_insert(index);
            facts.last_value_content = index + 1;
        }
    }
}

fn classify(byte: u8) -> WireByte {
    match byte {
        b':' => WireByte::Colon,
        b' ' | b'\t' => WireByte::Ows,
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => WireByte::Token,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_'
        | b'`' | b'|' | b'~' => WireByte::Token,
        0x21..=0x7e | 0x80..=0xff => WireByte::ValueOnly,
        _ => WireByte::Forbidden,
    }
}

fn build_header_block(input: &[u8], validated: ValidatedFields) -> HeaderBlock {
    let mut fields = Vec::with_capacity(validated.count);
    for layout in &validated.layouts[..validated.count] {
        let mut name = String::with_capacity(layout.name_end - layout.name_start);
        for byte in &input[layout.name_start..layout.name_end] {
            name.push(char::from(byte.to_ascii_lowercase()));
        }
        fields.push(HeaderField {
            name,
            value: input[layout.value_start..layout.value_end].to_vec(),
        });
    }
    HeaderBlock {
        fields,
        bytes_consumed: validated.bytes_consumed,
    }
}

fn invalid_header(index: usize, reason: &str) -> PolyguardError {
    PolyguardError::InvalidHeader {
        index,
        reason: reason.into(),
    }
}

fn limit_exceeded(limit: &str, max: usize, actual: usize) -> PolyguardError {
    PolyguardError::LimitExceeded {
        limit: limit.into(),
        max,
        actual,
    }
}
