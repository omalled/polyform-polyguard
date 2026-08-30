use std::collections::BTreeSet;

use crate::{HeaderBlock, HeaderField, PolyguardError, Result, SanitizedHeaders};

#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldPolicy {
    ConnectionList,
    AlwaysRemove,
}

const HOP_BY_HOP_RULES: [(&str, FieldPolicy); 9] = [
    ("connection", FieldPolicy::ConnectionList),
    ("proxy-connection", FieldPolicy::AlwaysRemove),
    ("keep-alive", FieldPolicy::AlwaysRemove),
    ("transfer-encoding", FieldPolicy::AlwaysRemove),
    ("te", FieldPolicy::AlwaysRemove),
    ("trailer", FieldPolicy::AlwaysRemove),
    ("upgrade", FieldPolicy::AlwaysRemove),
    ("proxy-authenticate", FieldPolicy::AlwaysRemove),
    ("proxy-authorization", FieldPolicy::AlwaysRemove),
];

struct RemovalPlan {
    names: BTreeSet<String>,
}

impl RemovalPlan {
    fn from_headers(headers: &HeaderBlock) -> Result<Self> {
        let mut names = BTreeSet::new();

        headers
            .fields
            .iter()
            .enumerate()
            .filter_map(|(index, field)| {
                field_policy(&field.name).map(|policy| (index, field, policy))
            })
            .try_for_each(|(index, field, policy)| match policy {
                FieldPolicy::ConnectionList => {
                    names.insert(field.name.clone());
                    add_connection_nominations(&mut names, &field.value, index)
                }
                FieldPolicy::AlwaysRemove => {
                    names.insert(field.name.clone());
                    Ok(())
                }
            })?;

        Ok(Self { names })
    }

    fn removes(&self, field: &&HeaderField) -> bool {
        self.names.contains(&field.name)
    }
}

/// Remove connection-specific metadata according to the fixed field rule table and
/// the complete set of names nominated by every Connection field.
pub(crate) fn remove_hop_by_hop_headers(headers: &HeaderBlock) -> Result<SanitizedHeaders> {
    let plan = RemovalPlan::from_headers(headers)?;
    let fields = headers
        .fields
        .iter()
        .filter(|field| !plan.removes(field))
        .cloned()
        .collect();

    Ok(SanitizedHeaders {
        fields,
        removed_names: plan.names.into_iter().collect(),
    })
}

fn field_policy(name: &str) -> Option<FieldPolicy> {
    HOP_BY_HOP_RULES
        .iter()
        .find_map(|(candidate, policy)| (*candidate == name).then_some(*policy))
}

fn add_connection_nominations(
    names: &mut BTreeSet<String>,
    value: &[u8],
    field_index: usize,
) -> Result<()> {
    value
        .split(|byte| *byte == b',')
        .map(trim_ows)
        .try_for_each(|member| {
            if member.is_empty() || !member.iter().copied().all(is_token_byte) {
                return Err(invalid_connection_token(field_index));
            }

            let canonical = member
                .iter()
                .map(u8::to_ascii_lowercase)
                .map(char::from)
                .collect();
            names.insert(canonical);
            Ok(())
        })
}

fn trim_ows(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let after_last = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(first, |index| index + 1);
    &bytes[first..after_last]
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

fn invalid_connection_token(index: usize) -> PolyguardError {
    PolyguardError::InvalidHeader {
        index,
        reason: "invalid_connection_token".into(),
    }
}
