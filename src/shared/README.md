# Shared Library

Shared Rust code used by both the Pigeon client and relay.

Expected responsibilities include:

- protocol types and wire formats
- serialization and shared errors
- cryptographic abstractions and identity types
- device credentials and signed metadata
- message, event, relay, and synchronization formats

This crate should remain platform-neutral.
