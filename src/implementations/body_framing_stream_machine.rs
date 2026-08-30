use crate::{BodyFraming, HeaderBlock, PolyguardError, RequestLine, Result};

const CONTENT_LENGTH_LIMIT: u64 = 16_777_216;

const SAW_CONTENT_LENGTH: u8 = 0b01;
const SAW_TRANSFER_ENCODING: u8 = 0b10;

const NO_FAULT: u8 = 0;
const BAD_CONTENT_LENGTH: u8 = 1;
const CONFLICTING_LENGTH: u8 = 2;
const EXCESSIVE_LENGTH: u8 = 3;
const BAD_TRANSFER_ENCODING: u8 = 4;

#[derive(Clone, Copy, Default)]
struct FramingMachine {
    presence: u8,
    agreed_length: u64,
    has_agreed_length: bool,
    transfer_members: usize,
    fault: u8,
    fault_actual: usize,
}

pub(crate) fn determine_body_framing(
    _request: &RequestLine,
    headers: &HeaderBlock,
) -> Result<BodyFraming> {
    let machine = headers
        .fields
        .iter()
        .fold(FramingMachine::default(), transition_field);

    finish(machine)
}

fn transition_field(mut machine: FramingMachine, field: &crate::HeaderField) -> FramingMachine {
    match field.name.as_str() {
        "content-length" => {
            machine.presence |= SAW_CONTENT_LENGTH;
            field
                .value
                .split(|byte| *byte == b',')
                .for_each(|member| observe_length(&mut machine, member));
        }
        "transfer-encoding" => {
            machine.presence |= SAW_TRANSFER_ENCODING;
            field
                .value
                .split(|byte| *byte == b',')
                .for_each(|member| observe_coding(&mut machine, member));
        }
        _ => {}
    }
    machine
}

fn observe_length(machine: &mut FramingMachine, raw: &[u8]) {
    match decimal_value(trim_ows(raw)) {
        Ok(value) if value > CONTENT_LENGTH_LIMIT => {
            remember_fault(
                machine,
                EXCESSIVE_LENGTH,
                usize::try_from(value).unwrap_or(usize::MAX),
            );
        }
        Ok(value) if machine.has_agreed_length && machine.agreed_length != value => {
            remember_fault(machine, CONFLICTING_LENGTH, 0);
        }
        Ok(value) => {
            machine.agreed_length = value;
            machine.has_agreed_length = true;
        }
        Err(()) => remember_fault(machine, BAD_CONTENT_LENGTH, 0),
    }
}

fn observe_coding(machine: &mut FramingMachine, raw: &[u8]) {
    machine.transfer_members += 1;
    let coding = trim_ows(raw);
    if machine.transfer_members != 1 || !coding.eq_ignore_ascii_case(b"chunked") {
        remember_fault(machine, BAD_TRANSFER_ENCODING, 0);
    }
}

fn decimal_value(bytes: &[u8]) -> std::result::Result<u64, ()> {
    if bytes.is_empty() {
        return Err(());
    }

    bytes.iter().try_fold(0_u64, |prefix, byte| {
        if !byte.is_ascii_digit() {
            return Err(());
        }
        prefix
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(*byte - b'0')))
            .ok_or(())
    })
}

fn remember_fault(machine: &mut FramingMachine, fault: u8, actual: usize) {
    if machine.fault == NO_FAULT {
        machine.fault = fault;
        machine.fault_actual = actual;
    }
}

fn finish(machine: FramingMachine) -> Result<BodyFraming> {
    if machine.presence == (SAW_CONTENT_LENGTH | SAW_TRANSFER_ENCODING) {
        return Err(PolyguardError::AmbiguousFraming);
    }

    match machine.fault {
        BAD_CONTENT_LENGTH => return Err(PolyguardError::InvalidContentLength),
        CONFLICTING_LENGTH => return Err(PolyguardError::ConflictingContentLength),
        EXCESSIVE_LENGTH => {
            return Err(PolyguardError::LimitExceeded {
                limit: "content_length".to_owned(),
                max: CONTENT_LENGTH_LIMIT as usize,
                actual: machine.fault_actual,
            });
        }
        BAD_TRANSFER_ENCODING => return Err(PolyguardError::InvalidTransferEncoding),
        _ => {}
    }

    match machine.presence {
        SAW_TRANSFER_ENCODING if machine.transfer_members == 1 => Ok(BodyFraming::Chunked),
        SAW_TRANSFER_ENCODING => Err(PolyguardError::InvalidTransferEncoding),
        SAW_CONTENT_LENGTH if machine.has_agreed_length && machine.agreed_length != 0 => {
            Ok(BodyFraming::ContentLength(machine.agreed_length))
        }
        _ => Ok(BodyFraming::None),
    }
}

fn trim_ows(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let width = bytes[first..]
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(0, |last| last + 1);
    &bytes[first..first + width]
}
