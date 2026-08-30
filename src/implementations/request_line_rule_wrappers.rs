use crate::{HttpVersion, PolyguardError, RequestLine, Result};

const REQUEST_LINE_LIMIT: usize = 8192;
const METHOD_LIMIT: usize = 32;

#[derive(Clone, Copy)]
enum BoundaryRule {
    Data,
    CarriageReturn,
    LineFeed,
    ForbiddenControl,
}

#[derive(Clone, Copy)]
enum TargetRule {
    Allowed,
    Fragment,
    NonVisible,
}

const BOUNDARY_RULES: [BoundaryRule; 128] = boundary_rules();
const METHOD_RULES: [bool; 128] = method_rules();
const TARGET_RULES: [TargetRule; 128] = target_rules();

const fn boundary_rules() -> [BoundaryRule; 128] {
    let mut rules = [BoundaryRule::Data; 128];
    let mut byte = 0;
    while byte < 32 {
        rules[byte] = BoundaryRule::ForbiddenControl;
        byte += 1;
    }
    // Horizontal tab is diagnosed by the grammar phase as invalid spacing.
    rules[b'\t' as usize] = BoundaryRule::Data;
    rules[b'\r' as usize] = BoundaryRule::CarriageReturn;
    rules[b'\n' as usize] = BoundaryRule::LineFeed;
    rules[127] = BoundaryRule::ForbiddenControl;
    rules
}

const fn method_rules() -> [bool; 128] {
    let mut rules = [false; 128];
    let mut byte = b'0';
    while byte <= b'9' {
        rules[byte as usize] = true;
        byte += 1;
    }
    byte = b'A';
    while byte <= b'Z' {
        rules[byte as usize] = true;
        byte += 1;
    }
    byte = b'a';
    while byte <= b'z' {
        rules[byte as usize] = true;
        byte += 1;
    }
    let punctuation = b"!#$%&'*+-.^_`|~";
    let mut index = 0;
    while index < punctuation.len() {
        rules[punctuation[index] as usize] = true;
        index += 1;
    }
    rules
}

const fn target_rules() -> [TargetRule; 128] {
    let mut rules = [TargetRule::NonVisible; 128];
    let mut byte = b'!';
    while byte <= b'~' {
        rules[byte as usize] = TargetRule::Allowed;
        byte += 1;
    }
    rules[b'#' as usize] = TargetRule::Fragment;
    rules
}

struct BoundaryCheckedLine<'a> {
    content: &'a [u8],
    bytes_consumed: usize,
}

struct GrammarParts<'a> {
    method: &'a [u8],
    target: &'a [u8],
    version: &'a [u8],
    bytes_consumed: usize,
}

struct ValidMethod(String);
struct ValidTarget(String);

pub(crate) fn parse_request_line(input: &[u8]) -> Result<RequestLine> {
    // Phase 1 validates the public byte boundary before later phases trust the line slice.
    let line = validate_boundary(input)?;
    // Phase 2 applies the exact three-field grammar without interpreting field contents.
    let parts = apply_grammar(line)?;
    // Phase 3 converts individually validated fields into their type-directed wrappers.
    let method = ValidMethod::try_from(parts.method)?;
    let target = ValidTarget::try_from(parts.target)?;
    validate_version(parts.version)?;

    Ok(RequestLine {
        method: method.0,
        target: target.0,
        version: HttpVersion::Http11,
        bytes_consumed: parts.bytes_consumed,
    })
}

fn validate_boundary(input: &[u8]) -> Result<BoundaryCheckedLine<'_>> {
    for (offset, &byte) in input.iter().take(REQUEST_LINE_LIMIT + 1).enumerate() {
        if offset == REQUEST_LINE_LIMIT {
            if input.get(offset..offset + 2) == Some(b"\r\n") {
                return Ok(BoundaryCheckedLine {
                    content: &input[..offset],
                    bytes_consumed: offset + 2,
                });
            }
            return Err(PolyguardError::LimitExceeded {
                limit: "request_line_bytes".into(),
                max: REQUEST_LINE_LIMIT,
                actual: REQUEST_LINE_LIMIT + 1,
            });
        }

        let rule = if byte.is_ascii() {
            BOUNDARY_RULES[byte as usize]
        } else {
            BoundaryRule::Data
        };
        match rule {
            BoundaryRule::CarriageReturn if input.get(offset + 1) == Some(&b'\n') => {
                return Ok(BoundaryCheckedLine {
                    content: &input[..offset],
                    bytes_consumed: offset + 2,
                });
            }
            BoundaryRule::CarriageReturn | BoundaryRule::LineFeed => {
                return Err(invalid_request_line("bare_line_ending"));
            }
            BoundaryRule::ForbiddenControl => {
                return Err(invalid_request_line("control_character"));
            }
            BoundaryRule::Data => {}
        }
    }

    Err(PolyguardError::Incomplete)
}

fn apply_grammar(line: BoundaryCheckedLine<'_>) -> Result<GrammarParts<'_>> {
    if line.content.contains(&b'\t') {
        return Err(invalid_request_line("invalid_spacing"));
    }

    let fields: Vec<&[u8]> = line.content.split(|byte| *byte == b' ').collect();
    match fields.as_slice() {
        [method, target, version]
            if !method.is_empty() && !target.is_empty() && !version.is_empty() =>
        {
            Ok(GrammarParts {
                method,
                target,
                version,
                bytes_consumed: line.bytes_consumed,
            })
        }
        [method, target] if !method.is_empty() && !target.is_empty() => {
            Err(PolyguardError::UnsupportedVersion)
        }
        _ => Err(invalid_request_line("invalid_spacing")),
    }
}

impl TryFrom<&[u8]> for ValidMethod {
    type Error = PolyguardError;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let valid_length = (1..=METHOD_LIMIT).contains(&bytes.len());
        let valid_bytes = bytes
            .iter()
            .all(|&byte| byte.is_ascii() && METHOD_RULES[byte as usize]);
        if !valid_length || !valid_bytes {
            return Err(PolyguardError::InvalidMethod);
        }

        let canonical = bytes.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
        Ok(Self(
            String::from_utf8(canonical).expect("token bytes are ASCII"),
        ))
    }
}

impl TryFrom<&[u8]> for ValidTarget {
    type Error = PolyguardError;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > REQUEST_LINE_LIMIT {
            return Err(invalid_target("non_visible_ascii"));
        }

        for &byte in bytes {
            let rule = if byte.is_ascii() {
                TARGET_RULES[byte as usize]
            } else {
                TargetRule::NonVisible
            };
            match rule {
                TargetRule::Allowed => {}
                TargetRule::Fragment => return Err(invalid_target("fragment_not_allowed")),
                TargetRule::NonVisible => return Err(invalid_target("non_visible_ascii")),
            }
        }

        Ok(Self(
            String::from_utf8(bytes.to_vec()).expect("target bytes are visible ASCII"),
        ))
    }
}

fn validate_version(version: &[u8]) -> Result<()> {
    if version == b"HTTP/1.1" {
        Ok(())
    } else {
        Err(PolyguardError::UnsupportedVersion)
    }
}

fn invalid_request_line(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidRequestLine {
        reason: reason.into(),
    }
}

fn invalid_target(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidTarget {
        reason: reason.into(),
    }
}
