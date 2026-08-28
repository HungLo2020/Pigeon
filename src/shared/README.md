# Shared Library

Shared Rust code used by both the Pigeon client and server.

Expected responsibilities include:

- protocol types and wire formats
- serialization and shared errors
- cryptographic abstractions and identity types
- device credentials and signed metadata
- signed, versioned routing records
- server migration events
- message and conversation event formats
- per-device delivery acknowledgements
- synchronization and retention metadata

The shared protocol must distinguish stable cryptographic identity from mutable server routing information and support the 14-day-or-all-devices-delivered server retention rule.

This crate should remain platform-neutral.
