//! Monotonic contact-route selection; cryptographic verification remains at
//! the network boundary in the client command flow.

use pigeon_shared::{routing_precedes, RoutingRecord};

pub(super) fn should_replace_route(
    current: Option<&RoutingRecord>,
    candidate: &RoutingRecord,
) -> bool {
    match current {
        None => true,
        Some(current) if candidate.revision > current.revision => true,
        Some(current)
            if candidate.revision == current.revision
                && candidate.parent_revision == current.parent_revision =>
        {
            routing_precedes(candidate, current)
        }
        _ => false,
    }
}
