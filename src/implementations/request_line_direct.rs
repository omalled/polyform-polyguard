use crate::{HttpVersion, PolyguardError, RequestLine, Result};

const MAX_LINE_CONTENT: usize = 8192;
const MAX_METHOD_BYTES: usize = 32;

pub(crate) fn parse_request_line(input: &[u8]) -> Result<RequestLine> {
    let line_length = find_terminator(input)?;
    let line = &input[..line_length];

    if line.contains(&b'\t') {
        return Err(invalid_line("invalid_spacing"));
    }

    let Some(method_end) = line.iter().position(|&byte| byte == b' ') else {
        return Err(invalid_line("invalid_spacing"));
    };
    if method_end == 0 {
        return Err(invalid_line("invalid_spacing"));
    }

    let target_start = method_end + 1;
    let Some(relative_target_end) = line[target_start..].iter().position(|&byte| byte == b' ')
    else {
        if target_start < line_length {
            return Err(PolyguardError::UnsupportedVersion);
        }
        return Err(invalid_line("invalid_spacing"));
    };
    let target_end = target_start + relative_target_end;
    if target_end == target_start {
        return Err(invalid_line("invalid_spacing"));
    }

    let version_start = target_end + 1;
    if version_start == line_length || line[version_start..].contains(&b' ') {
        return Err(invalid_line("invalid_spacing"));
    }

    let method_bytes = &line[..method_end];
    if method_bytes.len() > MAX_METHOD_BYTES || !method_bytes.iter().copied().all(is_token_byte) {
        return Err(PolyguardError::InvalidMethod);
    }

    let target_bytes = &line[target_start..target_end];
    if target_bytes.len() > MAX_LINE_CONTENT {
        return Err(PolyguardError::InvalidTarget {
            reason: "non_visible_ascii".into(),
        });
    }
    for &byte in target_bytes {
        if byte == b'#' {
            return Err(PolyguardError::InvalidTarget {
                reason: "fragment_not_allowed".into(),
            });
        }
        if !(b'!'..=b'~').contains(&byte) {
            return Err(PolyguardError::InvalidTarget {
                reason: "non_visible_ascii".into(),
            });
        }
    }

    if &line[version_start..] != b"HTTP/1.1" {
        return Err(PolyguardError::UnsupportedVersion);
    }

    let method = method_bytes
        .iter()
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect();
    let target = String::from_utf8(target_bytes.to_vec()).expect("visible ASCII target");

    Ok(RequestLine {
        method,
        target,
        version: HttpVersion::Http11,
        bytes_consumed: line_length + 2,
    })
}

fn find_terminator(input: &[u8]) -> Result<usize> {
    let mut offset = 0;
    while offset < input.len() {
        if offset == MAX_LINE_CONTENT {
            if input[offset] == b'\r' && input.get(offset + 1) == Some(&b'\n') {
                return Ok(offset);
            }
            return Err(PolyguardError::LimitExceeded {
                limit: "request_line_bytes".into(),
                max: MAX_LINE_CONTENT,
                actual: MAX_LINE_CONTENT + 1,
            });
        }

        let byte = input[offset];
        if byte == b'\r' {
            if input.get(offset + 1) == Some(&b'\n') {
                return Ok(offset);
            }
            return Err(invalid_line("bare_line_ending"));
        }
        if byte == b'\n' {
            return Err(invalid_line("bare_line_ending"));
        }
        if byte <= 8 || (11..=12).contains(&byte) || (14..=31).contains(&byte) || byte == 127 {
            return Err(invalid_line("control_character"));
        }

        offset += 1;
    }

    Err(PolyguardError::Incomplete)
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

fn invalid_line(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidRequestLine {
        reason: reason.into(),
    }
}
