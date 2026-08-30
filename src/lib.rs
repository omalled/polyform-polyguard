//! Shared Polyguard data model and implementation registry.
//!
//! Generated implementations register function pointers here.  Conformance tests and the
//! differential driver deliberately use this one registry so no implementation gets a
//! private or weakened copy of the tests.

use serde::{Deserialize, Serialize};

mod implementations;
pub mod proxy;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderField {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderBlock {
    pub fields: Vec<HeaderField>,
    pub bytes_consumed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestLine {
    pub method: String,
    pub target: String,
    pub version: HttpVersion,
    pub bytes_consumed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpVersion {
    Http11,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyFraming {
    None,
    ContentLength(u64),
    Chunked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkMeta {
    pub size: u64,
    pub extensions: Vec<ChunkExtension>,
    pub bytes_consumed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkExtension {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrailerBlock {
    pub fields: Vec<HeaderField>,
    pub bytes_consumed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetForm {
    Origin,
    Absolute,
    Authority,
    Asterisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedTarget {
    pub form: TargetForm,
    pub scheme: Option<String>,
    pub authority: Option<String>,
    pub path_and_query: String,
    pub routing_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveAuthority {
    pub host: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedHeaders {
    pub fields: Vec<HeaderField>,
    pub removed_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalRequestHead {
    pub bytes: Vec<u8>,
    pub body_framing: BodyFraming,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRule {
    pub host: String,
    pub path_prefix: String,
    pub upstream: String,
    pub declaration_order: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteMatch {
    pub upstream: String,
    pub declaration_order: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardingPolicy {
    pub trust_incoming: bool,
    pub client_ip: String,
    pub proto: String,
    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardingResult {
    pub forwarded: String,
    pub x_forwarded_for: String,
    pub x_forwarded_proto: String,
    pub x_forwarded_host: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeDecision {
    Reject,
    WebSocket,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryOutcome {
    pub category: OutcomeCategory,
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeCategory {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolyguardError {
    Incomplete,
    LimitExceeded {
        limit: String,
        max: usize,
        actual: usize,
    },
    InvalidRequestLine {
        reason: String,
    },
    UnsupportedVersion,
    InvalidMethod,
    InvalidTarget {
        reason: String,
    },
    InvalidHeader {
        index: usize,
        reason: String,
    },
    TooManyHeaders,
    InvalidContentLength,
    ConflictingContentLength,
    InvalidTransferEncoding,
    AmbiguousFraming,
    InvalidChunk {
        reason: String,
    },
    InvalidTrailer {
        reason: String,
    },
    MissingHost,
    MultipleHost,
    AuthorityMismatch,
    InvalidAuthority,
    InvalidRoute {
        reason: String,
    },
    NoRoute,
    InvalidForwardingInput,
    UnsupportedUpgrade,
    SerializationInvariant,
}

pub type Result<T> = std::result::Result<T, PolyguardError>;

pub type ParseRequestLineFn = fn(&[u8]) -> Result<RequestLine>;
pub type ParseHeaderSectionFn = fn(&[u8]) -> Result<HeaderBlock>;
pub type DetermineBodyFramingFn = fn(&RequestLine, &HeaderBlock) -> Result<BodyFraming>;
pub type ParseChunkMetadataFn = fn(&[u8]) -> Result<ChunkMeta>;
pub type ParseTrailerSectionFn = fn(&[u8], &[String]) -> Result<TrailerBlock>;
pub type NormalizeRequestTargetFn = fn(&RequestLine) -> Result<NormalizedTarget>;
pub type ReconcileAuthorityFn = fn(&NormalizedTarget, &HeaderBlock) -> Result<EffectiveAuthority>;
pub type RemoveHopByHopHeadersFn = fn(&HeaderBlock) -> Result<SanitizedHeaders>;
pub type ConstructCanonicalUpstreamHeadFn = fn(
    &str,
    &NormalizedTarget,
    &EffectiveAuthority,
    &SanitizedHeaders,
    &BodyFraming,
    &ForwardingResult,
) -> Result<CanonicalRequestHead>;
pub type MatchRouteFn =
    fn(&EffectiveAuthority, &NormalizedTarget, &[RouteRule]) -> Result<RouteMatch>;
pub type ApplyForwardingPolicyFn = fn(&ForwardingPolicy, &HeaderBlock) -> Result<ForwardingResult>;
pub type DecideUpgradeFn = fn(&RequestLine, &HeaderBlock, &BodyFraming) -> Result<UpgradeDecision>;
pub type ClassifyTelemetryOutcomeFn = fn(&str, bool) -> Result<TelemetryOutcome>;

#[derive(Clone, Copy)]
pub struct Implementation {
    pub id: &'static str,
    pub parse_request_line: Option<ParseRequestLineFn>,
    pub parse_header_section: Option<ParseHeaderSectionFn>,
    pub determine_body_framing: Option<DetermineBodyFramingFn>,
    pub parse_chunk_metadata: Option<ParseChunkMetadataFn>,
    pub parse_trailer_section: Option<ParseTrailerSectionFn>,
    pub normalize_request_target: Option<NormalizeRequestTargetFn>,
    pub reconcile_authority: Option<ReconcileAuthorityFn>,
    pub remove_hop_by_hop_headers: Option<RemoveHopByHopHeadersFn>,
    pub construct_canonical_upstream_head: Option<ConstructCanonicalUpstreamHeadFn>,
    pub match_route: Option<MatchRouteFn>,
    pub apply_forwarding_policy: Option<ApplyForwardingPolicyFn>,
    pub decide_upgrade: Option<DecideUpgradeFn>,
    pub classify_telemetry_outcome: Option<ClassifyTelemetryOutcomeFn>,
}

impl Implementation {
    pub const fn empty(id: &'static str) -> Self {
        Self {
            id,
            parse_request_line: None,
            parse_header_section: None,
            determine_body_framing: None,
            parse_chunk_metadata: None,
            parse_trailer_section: None,
            normalize_request_target: None,
            reconcile_authority: None,
            remove_hop_by_hop_headers: None,
            construct_canonical_upstream_head: None,
            match_route: None,
            apply_forwarding_policy: None,
            decide_upgrade: None,
            classify_telemetry_outcome: None,
        }
    }
}

/// Generated implementations append stable, unique entries to this slice.
pub fn registered_implementations() -> &'static [Implementation] {
    static IMPLEMENTATIONS: [Implementation; 65] = [
        Implementation {
            id: "request-line-state-pipeline",
            parse_request_line: Some(implementations::request_line_state::parse_request_line),
            ..Implementation::empty("request-line-state-pipeline")
        },
        Implementation {
            id: "request-line-direct-guards",
            parse_request_line: Some(implementations::request_line_direct::parse_request_line),
            ..Implementation::empty("request-line-direct-guards")
        },
        Implementation {
            id: "request-line-rule-wrappers",
            parse_request_line: Some(
                implementations::request_line_rule_wrappers::parse_request_line,
            ),
            ..Implementation::empty("request-line-rule-wrappers")
        },
        Implementation {
            id: "request-line-decision-machine",
            parse_request_line: Some(
                implementations::request_line_decision_machine::parse_request_line,
            ),
            ..Implementation::empty("request-line-decision-machine")
        },
        Implementation {
            id: "request-line-reverse-offsets",
            parse_request_line: Some(
                implementations::request_line_reverse_offsets::parse_request_line,
            ),
            ..Implementation::empty("request-line-reverse-offsets")
        },
        Implementation {
            id: "header-section-typed-cursor",
            parse_header_section: Some(implementations::header_typed_cursor::parse_header_section),
            ..Implementation::empty("header-section-typed-cursor")
        },
        Implementation {
            id: "header-section-state-phases",
            parse_header_section: Some(implementations::header_state_phases::parse_header_section),
            ..Implementation::empty("header-section-state-phases")
        },
        Implementation {
            id: "header-section-decision-table",
            parse_header_section: Some(
                implementations::header_decision_table::parse_header_section,
            ),
            ..Implementation::empty("header-section-decision-table")
        },
        Implementation {
            id: "header-section-algebraic-lines",
            parse_header_section: Some(
                implementations::header_algebraic_lines::parse_header_section,
            ),
            ..Implementation::empty("header-section-algebraic-lines")
        },
        Implementation {
            id: "header-section-transition-reducer",
            parse_header_section: Some(
                implementations::header_transition_reducer::parse_header_section,
            ),
            ..Implementation::empty("header-section-transition-reducer")
        },
        Implementation {
            id: "body-framing-metadata-transition",
            determine_body_framing: Some(
                implementations::body_framing_transition::determine_body_framing,
            ),
            ..Implementation::empty("body-framing-metadata-transition")
        },
        Implementation {
            id: "body-framing-direct-wrappers",
            determine_body_framing: Some(
                implementations::body_framing_direct::determine_body_framing,
            ),
            ..Implementation::empty("body-framing-direct-wrappers")
        },
        Implementation {
            id: "body-framing-rule-matrix",
            determine_body_framing: Some(
                implementations::body_framing_rule_matrix::determine_body_framing,
            ),
            ..Implementation::empty("body-framing-rule-matrix")
        },
        Implementation {
            id: "body-framing-stream-machine",
            determine_body_framing: Some(
                implementations::body_framing_stream_machine::determine_body_framing,
            ),
            ..Implementation::empty("body-framing-stream-machine")
        },
        Implementation {
            id: "body-framing-bounded-domain",
            determine_body_framing: Some(
                implementations::body_framing_bounded_domain::determine_body_framing,
            ),
            ..Implementation::empty("body-framing-bounded-domain")
        },
        Implementation {
            id: "chunk-metadata-rule-pipeline",
            parse_chunk_metadata: Some(implementations::chunk_rule_pipeline::parse_chunk_metadata),
            ..Implementation::empty("chunk-metadata-rule-pipeline")
        },
        Implementation {
            id: "chunk-metadata-guarded-parts",
            parse_chunk_metadata: Some(implementations::chunk_guarded_parts::parse_chunk_metadata),
            ..Implementation::empty("chunk-metadata-guarded-parts")
        },
        Implementation {
            id: "chunk-metadata-invariant-spans",
            parse_chunk_metadata: Some(
                implementations::chunk_invariant_spans::parse_chunk_metadata,
            ),
            ..Implementation::empty("chunk-metadata-invariant-spans")
        },
        Implementation {
            id: "chunk-metadata-symbol-rule-iterator",
            parse_chunk_metadata: Some(
                implementations::chunk_symbol_rule_iterator::parse_chunk_metadata,
            ),
            ..Implementation::empty("chunk-metadata-symbol-rule-iterator")
        },
        Implementation {
            id: "chunk-metadata-composable-segments",
            parse_chunk_metadata: Some(
                implementations::chunk_composable_segments::parse_chunk_metadata,
            ),
            ..Implementation::empty("chunk-metadata-composable-segments")
        },
        Implementation {
            id: "trailer-section-invariant-trie",
            parse_trailer_section: Some(
                implementations::trailer_invariant_trie::parse_trailer_section,
            ),
            ..Implementation::empty("trailer-section-invariant-trie")
        },
        Implementation {
            id: "trailer-section-transition-phases",
            parse_trailer_section: Some(
                implementations::trailer_transition_phases::parse_trailer_section,
            ),
            ..Implementation::empty("trailer-section-transition-phases")
        },
        Implementation {
            id: "trailer-section-direct-decision-table",
            parse_trailer_section: Some(
                implementations::trailer_direct_table::parse_trailer_section,
            ),
            ..Implementation::empty("trailer-section-direct-decision-table")
        },
        Implementation {
            id: "trailer-section-validated-invariants",
            parse_trailer_section: Some(
                implementations::trailer_validated_invariants::parse_trailer_section,
            ),
            ..Implementation::empty("trailer-section-validated-invariants")
        },
        Implementation {
            id: "trailer-section-event-automaton",
            parse_trailer_section: Some(
                implementations::trailer_event_automaton::parse_trailer_section,
            ),
            ..Implementation::empty("trailer-section-event-automaton")
        },
        Implementation {
            id: "request-target-rule-table",
            normalize_request_target: Some(
                implementations::request_target_rules::normalize_request_target,
            ),
            ..Implementation::empty("request-target-rule-table")
        },
        Implementation {
            id: "request-target-validated-pipeline",
            normalize_request_target: Some(
                implementations::request_target_validated_pipeline::normalize_request_target,
            ),
            ..Implementation::empty("request-target-validated-pipeline")
        },
        Implementation {
            id: "request-target-invariant-offsets",
            normalize_request_target: Some(
                implementations::request_target_invariant_offsets::normalize_request_target,
            ),
            ..Implementation::empty("request-target-invariant-offsets")
        },
        Implementation {
            id: "request-target-typed-rule-matrix",
            normalize_request_target: Some(
                implementations::request_target_typed_matrix::normalize_request_target,
            ),
            ..Implementation::empty("request-target-typed-rule-matrix")
        },
        Implementation {
            id: "request-target-composable-validators",
            normalize_request_target: Some(
                implementations::request_target_composable_validators::normalize_request_target,
            ),
            ..Implementation::empty("request-target-composable-validators")
        },
        Implementation {
            id: "authority-validation-phases",
            reconcile_authority: Some(implementations::authority_phases::reconcile_authority),
            ..Implementation::empty("authority-validation-phases")
        },
        Implementation {
            id: "authority-invariant-decision-table",
            reconcile_authority: Some(
                implementations::authority_invariant_table::reconcile_authority,
            ),
            ..Implementation::empty("authority-invariant-decision-table")
        },
        Implementation {
            id: "authority-composable-components",
            reconcile_authority: Some(
                implementations::authority_composable_components::reconcile_authority,
            ),
            ..Implementation::empty("authority-composable-components")
        },
        Implementation {
            id: "authority-segment-pipeline",
            reconcile_authority: Some(
                implementations::authority_segment_pipeline::reconcile_authority,
            ),
            ..Implementation::empty("authority-segment-pipeline")
        },
        Implementation {
            id: "authority-endpoint-algebra",
            reconcile_authority: Some(
                implementations::authority_endpoint_algebra::reconcile_authority,
            ),
            ..Implementation::empty("authority-endpoint-algebra")
        },
        Implementation {
            id: "hop-by-hop-rule-table",
            remove_hop_by_hop_headers: Some(
                implementations::hop_by_hop_rule_table::remove_hop_by_hop_headers,
            ),
            ..Implementation::empty("hop-by-hop-rule-table")
        },
        Implementation {
            id: "hop-by-hop-composable-guards",
            remove_hop_by_hop_headers: Some(
                implementations::hop_by_hop_composable::remove_hop_by_hop_headers,
            ),
            ..Implementation::empty("hop-by-hop-composable-guards")
        },
        Implementation {
            id: "hop-by-hop-typed-event-pipeline",
            remove_hop_by_hop_headers: Some(
                implementations::hop_by_hop_typed_pipeline::remove_hop_by_hop_headers,
            ),
            ..Implementation::empty("hop-by-hop-typed-event-pipeline")
        },
        Implementation {
            id: "hop-by-hop-sorted-rule-pipeline",
            remove_hop_by_hop_headers: Some(
                implementations::hop_by_hop_sorted_plan::remove_hop_by_hop_headers,
            ),
            ..Implementation::empty("hop-by-hop-sorted-rule-pipeline")
        },
        Implementation {
            id: "hop-by-hop-token-trie",
            remove_hop_by_hop_headers: Some(
                implementations::hop_by_hop_token_trie::remove_hop_by_hop_headers,
            ),
            ..Implementation::empty("hop-by-hop-token-trie")
        },
        Implementation {
            id: "canonical-head-rule-phases",
            construct_canonical_upstream_head: Some(
                implementations::canonical_head_rule_phases::construct_canonical_upstream_head,
            ),
            ..Implementation::empty("canonical-head-rule-phases")
        },
        Implementation {
            id: "canonical-head-composable-table",
            construct_canonical_upstream_head: Some(
                implementations::canonical_head_composable_table::construct_canonical_upstream_head,
            ),
            ..Implementation::empty("canonical-head-composable-table")
        },
        Implementation {
            id: "canonical-head-compiled-plan",
            construct_canonical_upstream_head: Some(
                implementations::canonical_head_compiled_plan::construct_canonical_upstream_head,
            ),
            ..Implementation::empty("canonical-head-compiled-plan")
        },
        Implementation {
            id: "canonical-head-dual-sink-rules",
            construct_canonical_upstream_head: Some(
                implementations::canonical_head_dual_sink_rules::construct_canonical_upstream_head,
            ),
            ..Implementation::empty("canonical-head-dual-sink-rules")
        },
        Implementation {
            id: "canonical-head-reverse-fill",
            construct_canonical_upstream_head: Some(
                implementations::canonical_head_reverse_fill::construct_canonical_upstream_head,
            ),
            ..Implementation::empty("canonical-head-reverse-fill")
        },
        Implementation {
            id: "route-direct-domain",
            match_route: Some(implementations::route_direct::match_route),
            ..Implementation::empty("route-direct-domain")
        },
        Implementation {
            id: "route-rule-validation-pipeline",
            match_route: Some(implementations::route_rule_pipeline::match_route),
            ..Implementation::empty("route-rule-validation-pipeline")
        },
        Implementation {
            id: "route-bounded-explicit-match",
            match_route: Some(implementations::route_bounded_match::match_route),
            ..Implementation::empty("route-bounded-explicit-match")
        },
        Implementation {
            id: "route-typed-arithmetic",
            match_route: Some(implementations::route_typed_arithmetic::match_route),
            ..Implementation::empty("route-typed-arithmetic")
        },
        Implementation {
            id: "route-immutable-validation-table",
            match_route: Some(implementations::route_immutable_table::match_route),
            ..Implementation::empty("route-immutable-validation-table")
        },
        Implementation {
            id: "forwarding-policy-decision-table",
            apply_forwarding_policy: Some(
                implementations::forwarding_decision_table::apply_forwarding_policy,
            ),
            ..Implementation::empty("forwarding-policy-decision-table")
        },
        Implementation {
            id: "forwarding-policy-direct-match",
            apply_forwarding_policy: Some(
                implementations::forwarding_direct_match::apply_forwarding_policy,
            ),
            ..Implementation::empty("forwarding-policy-direct-match")
        },
        Implementation {
            id: "forwarding-policy-transition-model",
            apply_forwarding_policy: Some(
                implementations::forwarding_transition_model::apply_forwarding_policy,
            ),
            ..Implementation::empty("forwarding-policy-transition-model")
        },
        Implementation {
            id: "forwarding-policy-central-transition-table",
            apply_forwarding_policy: Some(
                implementations::forwarding_central_transition::apply_forwarding_policy,
            ),
            ..Implementation::empty("forwarding-policy-central-transition-table")
        },
        Implementation {
            id: "forwarding-policy-primitive-boundary",
            apply_forwarding_policy: Some(
                implementations::forwarding_primitive_boundary::apply_forwarding_policy,
            ),
            ..Implementation::empty("forwarding-policy-primitive-boundary")
        },
        Implementation {
            id: "upgrade-composable-decision-table",
            decide_upgrade: Some(implementations::upgrade_composable_table::decide_upgrade),
            ..Implementation::empty("upgrade-composable-decision-table")
        },
        Implementation {
            id: "upgrade-invariant-signature",
            decide_upgrade: Some(implementations::upgrade_invariant_signature::decide_upgrade),
            ..Implementation::empty("upgrade-invariant-signature")
        },
        Implementation {
            id: "upgrade-observation-policy-table",
            decide_upgrade: Some(implementations::upgrade_observation_policy::decide_upgrade),
            ..Implementation::empty("upgrade-observation-policy-table")
        },
        Implementation {
            id: "upgrade-obligation-algebra",
            decide_upgrade: Some(implementations::upgrade_obligation_algebra::decide_upgrade),
            ..Implementation::empty("upgrade-obligation-algebra")
        },
        Implementation {
            id: "upgrade-transformation-matrix",
            decide_upgrade: Some(implementations::upgrade_transformation_matrix::decide_upgrade),
            ..Implementation::empty("upgrade-transformation-matrix")
        },
        Implementation {
            id: "telemetry-bounded-rule-table",
            classify_telemetry_outcome: Some(
                implementations::telemetry_rule_table::classify_telemetry_outcome,
            ),
            ..Implementation::empty("telemetry-bounded-rule-table")
        },
        Implementation {
            id: "telemetry-symbol-phases",
            classify_telemetry_outcome: Some(
                implementations::telemetry_symbol_phases::classify_telemetry_outcome,
            ),
            ..Implementation::empty("telemetry-symbol-phases")
        },
        Implementation {
            id: "telemetry-length-rule-dispatch",
            classify_telemetry_outcome: Some(
                implementations::telemetry_length_dispatch::classify_telemetry_outcome,
            ),
            ..Implementation::empty("telemetry-length-rule-dispatch")
        },
        Implementation {
            id: "telemetry-fingerprint-index",
            classify_telemetry_outcome: Some(
                implementations::telemetry_fingerprint_index::classify_telemetry_outcome,
            ),
            ..Implementation::empty("telemetry-fingerprint-index")
        },
        Implementation {
            id: "telemetry-word-composition",
            classify_telemetry_outcome: Some(
                implementations::telemetry_word_composition::classify_telemetry_outcome,
            ),
            ..Implementation::empty("telemetry-word-composition")
        },
    ];

    &IMPLEMENTATIONS
}
