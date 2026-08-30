use polyform_polyguard::{Implementation, registered_implementations};
use serde_json::{Value, json};

fn descriptor(implementation: &Implementation) -> Value {
    let provenance = match implementation.id {
        "request-line-state-pipeline" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/request_line_state.rs"
        }),
        "request-line-direct-guards" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/request_line_direct.rs"
        }),
        "request-line-rule-wrappers" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/request_line_rule_wrappers.rs"
        }),
        "request-line-decision-machine" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/request_line_decision_machine.rs"
        }),
        "request-line-reverse-offsets" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/request_line_reverse_offsets.rs"
        }),
        "header-section-typed-cursor" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/header_typed_cursor.rs"
        }),
        "header-section-state-phases" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/header_state_phases.rs"
        }),
        "header-section-decision-table" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/header_decision_table.rs"
        }),
        "header-section-algebraic-lines" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/header_algebraic_lines.rs"
        }),
        "header-section-transition-reducer" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/header_transition_reducer.rs"
        }),
        "body-framing-metadata-transition" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/body_framing_transition.rs"
        }),
        "body-framing-direct-wrappers" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/body_framing_direct.rs"
        }),
        "body-framing-rule-matrix" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/body_framing_rule_matrix.rs"
        }),
        "body-framing-stream-machine" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/body_framing_stream_machine.rs"
        }),
        "body-framing-bounded-domain" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/body_framing_bounded_domain.rs"
        }),
        "chunk-metadata-rule-pipeline" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/chunk_rule_pipeline.rs"
        }),
        "chunk-metadata-guarded-parts" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/chunk_guarded_parts.rs"
        }),
        "chunk-metadata-invariant-spans" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/chunk_invariant_spans.rs"
        }),
        "chunk-metadata-symbol-rule-iterator" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/chunk_symbol_rule_iterator.rs"
        }),
        "chunk-metadata-composable-segments" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/chunk_composable_segments.rs"
        }),
        "trailer-section-invariant-trie" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/trailer_invariant_trie.rs"
        }),
        "trailer-section-transition-phases" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/trailer_transition_phases.rs"
        }),
        "trailer-section-direct-decision-table" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/trailer_direct_table.rs"
        }),
        "trailer-section-validated-invariants" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/trailer_validated_invariants.rs"
        }),
        "trailer-section-event-automaton" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/trailer_event_automaton.rs"
        }),
        "request-target-rule-table" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/request_target_rules.rs"
        }),
        "request-target-validated-pipeline" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/request_target_validated_pipeline.rs"
        }),
        "request-target-invariant-offsets" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/request_target_invariant_offsets.rs"
        }),
        "request-target-typed-rule-matrix" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/request_target_typed_matrix.rs"
        }),
        "request-target-composable-validators" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/request_target_composable_validators.rs"
        }),
        "authority-validation-phases" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/authority_phases.rs"
        }),
        "authority-invariant-decision-table" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/authority_invariant_table.rs"
        }),
        "authority-composable-components" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/authority_composable_components.rs"
        }),
        "authority-segment-pipeline" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/authority_segment_pipeline.rs"
        }),
        "authority-endpoint-algebra" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/authority_endpoint_algebra.rs"
        }),
        "hop-by-hop-rule-table" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/hop_by_hop_rule_table.rs"
        }),
        "hop-by-hop-composable-guards" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/hop_by_hop_composable.rs"
        }),
        "hop-by-hop-typed-event-pipeline" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/hop_by_hop_typed_pipeline.rs"
        }),
        "hop-by-hop-sorted-rule-pipeline" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/hop_by_hop_sorted_plan.rs"
        }),
        "hop-by-hop-token-trie" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/hop_by_hop_token_trie.rs"
        }),
        "canonical-head-rule-phases" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/canonical_head_rule_phases.rs"
        }),
        "canonical-head-composable-table" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/canonical_head_composable_table.rs"
        }),
        "canonical-head-compiled-plan" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/canonical_head_compiled_plan.rs"
        }),
        "canonical-head-dual-sink-rules" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/canonical_head_dual_sink_rules.rs"
        }),
        "canonical-head-reverse-fill" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/canonical_head_reverse_fill.rs"
        }),
        "route-direct-domain" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/route_direct.rs"
        }),
        "route-rule-validation-pipeline" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/route_rule_pipeline.rs"
        }),
        "route-bounded-explicit-match" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/route_bounded_match.rs"
        }),
        "route-typed-arithmetic" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/route_typed_arithmetic.rs"
        }),
        "route-immutable-validation-table" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/route_immutable_table.rs"
        }),
        "forwarding-policy-decision-table" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/forwarding_decision_table.rs"
        }),
        "forwarding-policy-direct-match" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/forwarding_direct_match.rs"
        }),
        "forwarding-policy-transition-model" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/forwarding_transition_model.rs"
        }),
        "forwarding-policy-central-transition-table" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/forwarding_central_transition.rs"
        }),
        "forwarding-policy-primitive-boundary" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/forwarding_primitive_boundary.rs"
        }),
        "upgrade-composable-decision-table" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/upgrade_composable_table.rs"
        }),
        "upgrade-invariant-signature" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/upgrade_invariant_signature.rs"
        }),
        "upgrade-observation-policy-table" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/upgrade_observation_policy.rs"
        }),
        "upgrade-obligation-algebra" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/upgrade_obligation_algebra.rs"
        }),
        "upgrade-transformation-matrix" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/upgrade_transformation_matrix.rs"
        }),
        "telemetry-bounded-rule-table" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/telemetry_rule_table.rs"
        }),
        "telemetry-symbol-phases" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/telemetry_symbol_phases.rs"
        }),
        "telemetry-length-rule-dispatch" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/telemetry_length_dispatch.rs"
        }),
        "telemetry-fingerprint-index" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/telemetry_fingerprint_index.rs"
        }),
        "telemetry-word-composition" => json!({
            "generator": "polyform",
            "conformance": "accepted",
            "experimental": false,
            "path": "src/implementations/telemetry_word_composition.rs"
        }),
        unknown => panic!("missing release-manifest provenance for {unknown}"),
    };

    json!({
        "id": implementation.id,
        "name": implementation.id,
        "provenance": provenance
    })
}

macro_rules! inventory {
    ($registry:ident, $($field:ident),+ $(,)?) => {
        vec![
            $(json!({
                "name": stringify!($field),
                "implementations": $registry
                    .iter()
                    .filter(|implementation| implementation.$field.is_some())
                    .map(descriptor)
                    .collect::<Vec<_>>()
            })),+
        ]
    };
}

fn main() {
    let registry = registered_implementations();
    let spec_functions = inventory!(
        registry,
        parse_request_line,
        parse_header_section,
        determine_body_framing,
        parse_chunk_metadata,
        parse_trailer_section,
        normalize_request_target,
        reconcile_authority,
        remove_hop_by_hop_headers,
        construct_canonical_upstream_head,
        match_route,
        apply_forwarding_policy,
        decide_upgrade,
        classify_telemetry_outcome,
    );

    serde_json::to_writer(
        std::io::stdout().lock(),
        &json!({
            "application": "polyform-polyguard",
            "version": env!("CARGO_PKG_VERSION"),
            "spec_functions": spec_functions
        }),
    )
    .expect("write release manifest");
}
