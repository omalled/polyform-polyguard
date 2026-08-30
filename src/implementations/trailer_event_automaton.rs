use std::cmp::Ordering;

use crate::{HeaderField, PolyguardError, Result, TrailerBlock};

const SECTION_LIMIT: usize = 8_192;
const FIELD_LIMIT: usize = 32;
const NAME_LIMIT: usize = 128;
const VALUE_LIMIT: usize = 8_192;

enum DeclarationFact {
    Usable,
    Malformed,
    Forbidden,
}

struct DeclarationDomain<'a> {
    ordered: Vec<&'a str>,
}

#[derive(Clone, Copy)]
struct NameFacts {
    start: usize,
    length: usize,
    begins_with_ows: bool,
    contains_ows: bool,
    contains_non_token: bool,
}

#[derive(Clone, Copy)]
struct ValueFacts {
    name: NameFacts,
    name_end: usize,
    value_start: usize,
    first_content: Option<usize>,
    content_end: usize,
    contains_invalid_octet: bool,
}

#[derive(Clone, Copy)]
enum RawLine {
    MissingColon(NameFacts),
    Complete(ValueFacts),
}

#[derive(Clone, Copy)]
enum PendingLine {
    Terminator,
    Field(RawLine),
}

#[derive(Clone, Copy)]
enum MachineState {
    LineStart,
    Name(NameFacts),
    Value(ValueFacts),
    NeedLineFeed(PendingLine),
}

enum MachineEvent {
    Advance(MachineState),
    Emit(RawLine),
    Finish,
}

struct WireEnvelope {
    lines: Vec<RawLine>,
    bytes_consumed: usize,
}

#[derive(Clone, Copy)]
struct FieldPlan {
    name_start: usize,
    name_end: usize,
    value_start: usize,
    value_end: usize,
}

pub(crate) fn parse_trailer_section(
    input: &[u8],
    declared_names: &[String],
) -> Result<TrailerBlock> {
    let declarations = compile_declarations(declared_names)?;
    let envelope = run_wire_automaton(input)?;
    let plans = decide_field_grammar(&envelope.lines)?;
    enforce_trailer_policy(input, &plans, &declarations)?;
    Ok(materialize(input, plans, envelope.bytes_consumed))
}

fn compile_declarations(names: &[String]) -> Result<DeclarationDomain<'_>> {
    // Establish every per-name bound before allocating storage proportional to the collection.
    for name in names {
        match classify_declaration(name) {
            DeclarationFact::Usable => {}
            DeclarationFact::Malformed => return Err(invalid("invalid_declaration")),
            DeclarationFact::Forbidden => return Err(invalid("forbidden_field")),
        }
    }

    let mut ordered: Vec<&str> = names.iter().map(String::as_str).collect();
    ordered.sort_unstable();
    if ordered.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("duplicate_declaration"));
    }
    Ok(DeclarationDomain { ordered })
}

fn classify_declaration(name: &str) -> DeclarationFact {
    if name.is_empty()
        || name.len() > NAME_LIMIT
        || name.bytes().any(|byte| byte.is_ascii_uppercase())
        || !name.bytes().all(is_token_byte)
    {
        DeclarationFact::Malformed
    } else if is_forbidden_text(name) {
        DeclarationFact::Forbidden
    } else {
        DeclarationFact::Usable
    }
}

fn run_wire_automaton(input: &[u8]) -> Result<WireEnvelope> {
    let mut state = MachineState::LineStart;
    let mut cursor = 0usize;
    let mut lines = Vec::new();

    loop {
        if cursor == SECTION_LIMIT {
            if input.len() > SECTION_LIMIT {
                return Err(section_limit(SECTION_LIMIT + 1));
            }
            return end_of_input(state);
        }

        let Some(&byte) = input.get(cursor) else {
            return end_of_input(state);
        };

        match transition(state, cursor, byte).map_err(invalid)? {
            MachineEvent::Advance(next) => state = next,
            MachineEvent::Emit(line) => {
                if lines.len() == FIELD_LIMIT {
                    return Err(invalid("too_many_fields"));
                }
                lines.push(line);
                state = MachineState::LineStart;
            }
            MachineEvent::Finish => {
                return Ok(WireEnvelope {
                    lines,
                    bytes_consumed: cursor + 1,
                });
            }
        }
        cursor += 1;
    }
}

fn end_of_input<T>(state: MachineState) -> Result<T> {
    match state {
        MachineState::NeedLineFeed(_) => Err(invalid("bare_line_ending")),
        MachineState::LineStart | MachineState::Name(_) | MachineState::Value(_) => {
            Err(PolyguardError::Incomplete)
        }
    }
}

fn transition(
    state: MachineState,
    index: usize,
    byte: u8,
) -> std::result::Result<MachineEvent, &'static str> {
    match (state, byte) {
        (MachineState::LineStart, b'\r') => Ok(MachineEvent::Advance(MachineState::NeedLineFeed(
            PendingLine::Terminator,
        ))),
        (MachineState::LineStart, b'\n') => Err("bare_line_ending"),
        (MachineState::LineStart, symbol) => Ok(MachineEvent::Advance(consume_name(
            NameFacts {
                start: index,
                length: 0,
                begins_with_ows: matches!(symbol, b' ' | b'\t'),
                contains_ows: false,
                contains_non_token: false,
            },
            index,
            symbol,
        ))),

        (MachineState::Name(facts), b'\r') => Ok(MachineEvent::Advance(
            MachineState::NeedLineFeed(PendingLine::Field(RawLine::MissingColon(facts))),
        )),
        (MachineState::Name(_), b'\n') => Err("bare_line_ending"),
        (MachineState::Name(facts), symbol) => {
            Ok(MachineEvent::Advance(consume_name(facts, index, symbol)))
        }

        (MachineState::Value(facts), b'\r') => Ok(MachineEvent::Advance(
            MachineState::NeedLineFeed(PendingLine::Field(RawLine::Complete(facts))),
        )),
        (MachineState::Value(_), b'\n') => Err("bare_line_ending"),
        (MachineState::Value(facts), symbol) => Ok(MachineEvent::Advance(MachineState::Value(
            consume_value(facts, index, symbol),
        ))),

        (MachineState::NeedLineFeed(PendingLine::Terminator), b'\n') => Ok(MachineEvent::Finish),
        (MachineState::NeedLineFeed(PendingLine::Field(line)), b'\n') => {
            Ok(MachineEvent::Emit(line))
        }
        (MachineState::NeedLineFeed(_), _) => Err("bare_line_ending"),
    }
}

fn consume_name(facts: NameFacts, index: usize, byte: u8) -> MachineState {
    if byte == b':' {
        MachineState::Value(ValueFacts {
            name: facts,
            name_end: index,
            value_start: index + 1,
            first_content: None,
            content_end: index + 1,
            contains_invalid_octet: false,
        })
    } else {
        MachineState::Name(NameFacts {
            start: facts.start,
            length: facts.length + 1,
            begins_with_ows: facts.begins_with_ows,
            contains_ows: facts.contains_ows || matches!(byte, b' ' | b'\t'),
            contains_non_token: facts.contains_non_token || !is_token_byte(byte),
        })
    }
}

fn consume_value(facts: ValueFacts, index: usize, byte: u8) -> ValueFacts {
    let is_content = !matches!(byte, b' ' | b'\t');
    ValueFacts {
        name: facts.name,
        name_end: facts.name_end,
        value_start: facts.value_start,
        first_content: facts.first_content.or(is_content.then_some(index)),
        content_end: if is_content {
            index + 1
        } else {
            facts.content_end
        },
        contains_invalid_octet: facts.contains_invalid_octet || !is_value_byte(byte),
    }
}

fn decide_field_grammar(lines: &[RawLine]) -> Result<Vec<FieldPlan>> {
    lines.iter().copied().map(decide_one_field).collect()
}

fn decide_one_field(line: RawLine) -> Result<FieldPlan> {
    let name = match line {
        RawLine::MissingColon(name) if name.begins_with_ows => {
            return Err(invalid("obs_fold"));
        }
        RawLine::MissingColon(_) => return Err(invalid("invalid_name")),
        RawLine::Complete(value) if value.name.begins_with_ows => {
            return Err(invalid("obs_fold"));
        }
        RawLine::Complete(value) => value,
    };

    match (
        name.name.length,
        name.name.contains_ows,
        name.name.contains_non_token,
        name.contains_invalid_octet,
        name.first_content
            .map_or(0, |start| name.content_end - start),
    ) {
        (0, _, _, _, _) => Err(invalid("invalid_name")),
        (length, _, _, _, _) if length > NAME_LIMIT => Err(invalid("invalid_name")),
        (_, true, _, _, _) => Err(invalid("whitespace_before_colon")),
        (_, _, true, _, _) => Err(invalid("invalid_name")),
        (_, _, _, true, _) => Err(invalid("invalid_value_byte")),
        (_, _, _, _, length) if length > VALUE_LIMIT => Err(invalid("value_too_long")),
        _ => Ok(FieldPlan {
            name_start: name.name.start,
            name_end: name.name_end,
            value_start: name.first_content.unwrap_or(name.value_start),
            value_end: name.content_end,
        }),
    }
}

fn enforce_trailer_policy(
    input: &[u8],
    plans: &[FieldPlan],
    declarations: &DeclarationDomain<'_>,
) -> Result<()> {
    for (index, plan) in plans.iter().enumerate() {
        let wire_name = &input[plan.name_start..plan.name_end];
        if is_forbidden_wire(wire_name) {
            return Err(invalid("forbidden_field"));
        }
        if !declarations.contains_wire_name(wire_name) {
            return Err(invalid("undeclared_field"));
        }
        if plans[..index].iter().any(|earlier| {
            input[earlier.name_start..earlier.name_end].eq_ignore_ascii_case(wire_name)
        }) {
            return Err(invalid("duplicate_field"));
        }
    }
    Ok(())
}

impl DeclarationDomain<'_> {
    fn contains_wire_name(&self, wire: &[u8]) -> bool {
        let mut low = 0usize;
        let mut high = self.ordered.len();
        while low < high {
            let middle = low + (high - low) / 2;
            match compare_wire_name(wire, self.ordered[middle].as_bytes()) {
                Ordering::Less => high = middle,
                Ordering::Equal => return true,
                Ordering::Greater => low = middle + 1,
            }
        }
        false
    }
}

fn compare_wire_name(wire: &[u8], declaration: &[u8]) -> Ordering {
    wire.iter()
        .map(u8::to_ascii_lowercase)
        .cmp(declaration.iter().copied())
}

fn materialize(input: &[u8], plans: Vec<FieldPlan>, bytes_consumed: usize) -> TrailerBlock {
    let fields = plans
        .into_iter()
        .map(|plan| HeaderField {
            name: input[plan.name_start..plan.name_end]
                .iter()
                .map(|byte| char::from(byte.to_ascii_lowercase()))
                .collect(),
            value: input[plan.value_start..plan.value_end].to_vec(),
        })
        .collect();
    TrailerBlock {
        fields,
        bytes_consumed,
    }
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

fn is_value_byte(byte: u8) -> bool {
    byte == b'\t' || (b' '..=b'~').contains(&byte) || byte >= 0x80
}

fn is_forbidden_text(name: &str) -> bool {
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

fn is_forbidden_wire(name: &[u8]) -> bool {
    const EXACT: [&[u8]; 11] = [
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
    ];

    name.get(..b"x-forwarded-".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"x-forwarded-"))
        || EXACT
            .iter()
            .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
}

fn invalid(reason: &str) -> PolyguardError {
    PolyguardError::InvalidTrailer {
        reason: reason.into(),
    }
}

fn section_limit(actual: usize) -> PolyguardError {
    PolyguardError::LimitExceeded {
        limit: "trailer_bytes".into(),
        max: SECTION_LIMIT,
        actual,
    }
}
