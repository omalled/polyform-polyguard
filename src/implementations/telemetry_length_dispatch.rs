use crate::{OutcomeCategory, PolyguardError, Result, TelemetryOutcome};

const LONGEST_CODE: usize = "implementation_disagreement".len();

struct BoundedCode<'a>(&'a str);

impl<'a> BoundedCode<'a> {
    fn new(code: &'a str) -> Result<Self> {
        if code.len() > LONGEST_CODE {
            return Err(PolyguardError::SerializationInvariant);
        }
        Ok(Self(code))
    }

    fn text(&self) -> &'a str {
        self.0
    }
}

enum ReachabilityChecked {
    Any(TelemetryOutcome),
    BeforeUpstream(TelemetryOutcome),
}

impl ReachabilityChecked {
    fn release(self, upstream_reached: bool) -> Result<TelemetryOutcome> {
        if upstream_reached && matches!(self, Self::BeforeUpstream(_)) {
            return Err(PolyguardError::SerializationInvariant);
        }

        match self {
            Self::Any(outcome) | Self::BeforeUpstream(outcome) => Ok(outcome),
        }
    }
}

type LengthRule = fn(&str) -> Option<ReachabilityChecked>;

const LENGTH_RULES: [(usize, LengthRule); 7] = [
    (7, seven_byte_code),
    (8, eight_byte_code),
    (13, thirteen_byte_code),
    (15, fifteen_byte_code),
    (16, sixteen_byte_code),
    (17, seventeen_byte_code),
    (27, twenty_seven_byte_code),
];

fn outcome(category: OutcomeCategory, success: bool) -> TelemetryOutcome {
    TelemetryOutcome { category, success }
}

fn seven_byte_code(code: &str) -> Option<ReachabilityChecked> {
    (code == "timeout").then(|| ReachabilityChecked::Any(outcome(OutcomeCategory::Timeout, false)))
}

fn eight_byte_code(code: &str) -> Option<ReachabilityChecked> {
    (code == "accepted").then(|| ReachabilityChecked::Any(outcome(OutcomeCategory::Accepted, true)))
}

fn thirteen_byte_code(code: &str) -> Option<ReachabilityChecked> {
    let category = match code {
        "client_syntax" => OutcomeCategory::ClientSyntax,
        "route_missing" => OutcomeCategory::RouteMissing,
        _ => return None,
    };
    Some(ReachabilityChecked::BeforeUpstream(outcome(
        category, false,
    )))
}

fn fifteen_byte_code(code: &str) -> Option<ReachabilityChecked> {
    (code == "policy_rejected").then(|| {
        ReachabilityChecked::BeforeUpstream(outcome(OutcomeCategory::PolicyRejected, false))
    })
}

fn sixteen_byte_code(code: &str) -> Option<ReachabilityChecked> {
    let category = match code {
        "upstream_failure" => OutcomeCategory::UpstreamFailure,
        "internal_failure" => OutcomeCategory::InternalFailure,
        _ => return None,
    };
    Some(ReachabilityChecked::Any(outcome(category, false)))
}

fn seventeen_byte_code(code: &str) -> Option<ReachabilityChecked> {
    (code == "ambiguous_framing").then(|| {
        ReachabilityChecked::BeforeUpstream(outcome(OutcomeCategory::AmbiguousFraming, false))
    })
}

fn twenty_seven_byte_code(code: &str) -> Option<ReachabilityChecked> {
    (code == "implementation_disagreement").then(|| {
        ReachabilityChecked::BeforeUpstream(outcome(
            OutcomeCategory::ImplementationDisagreement,
            false,
        ))
    })
}

/// Classify a bounded fixed code through length-specific rules.
pub fn classify_telemetry_outcome(code: &str, upstream_reached: bool) -> Result<TelemetryOutcome> {
    let code = BoundedCode::new(code)?;

    let Some((_, classify)) = LENGTH_RULES
        .iter()
        .find(|(length, _)| *length == code.text().len())
    else {
        return Err(PolyguardError::SerializationInvariant);
    };

    let Some(classified) = classify(code.text()) else {
        return Err(PolyguardError::SerializationInvariant);
    };

    classified.release(upstream_reached)
}
