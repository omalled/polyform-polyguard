use crate::{OutcomeCategory, PolyguardError, Result, TelemetryOutcome};

#[derive(Clone, Copy)]
enum OutcomeSymbol {
    Accepted,
    ClientSyntax,
    AmbiguousFraming,
    PolicyRejected,
    RouteMissing,
    UpstreamFailure,
    Timeout,
    ImplementationDisagreement,
    InternalFailure,
}

fn decode_boundary(code: &str) -> Result<OutcomeSymbol> {
    match code {
        "accepted" => Ok(OutcomeSymbol::Accepted),
        "client_syntax" => Ok(OutcomeSymbol::ClientSyntax),
        "ambiguous_framing" => Ok(OutcomeSymbol::AmbiguousFraming),
        "policy_rejected" => Ok(OutcomeSymbol::PolicyRejected),
        "route_missing" => Ok(OutcomeSymbol::RouteMissing),
        "upstream_failure" => Ok(OutcomeSymbol::UpstreamFailure),
        "timeout" => Ok(OutcomeSymbol::Timeout),
        "implementation_disagreement" => Ok(OutcomeSymbol::ImplementationDisagreement),
        "internal_failure" => Ok(OutcomeSymbol::InternalFailure),
        _ => Err(PolyguardError::SerializationInvariant),
    }
}

fn permits_upstream(symbol: OutcomeSymbol) -> bool {
    matches!(
        symbol,
        OutcomeSymbol::Accepted
            | OutcomeSymbol::UpstreamFailure
            | OutcomeSymbol::Timeout
            | OutcomeSymbol::InternalFailure
    )
}

fn project(symbol: OutcomeSymbol) -> TelemetryOutcome {
    let (category, success) = match symbol {
        OutcomeSymbol::Accepted => (OutcomeCategory::Accepted, true),
        OutcomeSymbol::ClientSyntax => (OutcomeCategory::ClientSyntax, false),
        OutcomeSymbol::AmbiguousFraming => (OutcomeCategory::AmbiguousFraming, false),
        OutcomeSymbol::PolicyRejected => (OutcomeCategory::PolicyRejected, false),
        OutcomeSymbol::RouteMissing => (OutcomeCategory::RouteMissing, false),
        OutcomeSymbol::UpstreamFailure => (OutcomeCategory::UpstreamFailure, false),
        OutcomeSymbol::Timeout => (OutcomeCategory::Timeout, false),
        OutcomeSymbol::ImplementationDisagreement => {
            (OutcomeCategory::ImplementationDisagreement, false)
        }
        OutcomeSymbol::InternalFailure => (OutcomeCategory::InternalFailure, false),
    };

    TelemetryOutcome { category, success }
}

/// Classify a validated internal symbol into fixed, privacy-safe telemetry.
pub fn classify_telemetry_outcome(code: &str, upstream_reached: bool) -> Result<TelemetryOutcome> {
    let symbol = decode_boundary(code)?;

    if upstream_reached && !permits_upstream(symbol) {
        return Err(PolyguardError::SerializationInvariant);
    }

    Ok(project(symbol))
}
