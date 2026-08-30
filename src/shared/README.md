# Shared Library

Shared Rust code used by both the Pigeon client and server.

Expected responsibilities include:

- protocol types and wire formats
- serialization and shared errors
- cryptographic abstractions and identity types
- device credentials and signed metadata
- active/dormant/revoked device-state types
- signed device-revocation records
- signed, versioned routing records
- server migration events
- message and conversation event formats
- per-device delivery acknowledgements
- synchronization and retention metadata

The shared protocol must distinguish stable cryptographic identity from mutable server routing information, distinguish device authorization from delivery status, and support the 14-day-or-all-active-devices-delivered server retention rule plus the 90-day dormancy rule.

`PigeonAccountGenesis` is the authoritative identity anchor. Its SHA-256
compact ID is never an equality or authorization primitive by itself: account
selection messages must bind canonical genesis, and compact-ID collisions must
remain isolated.

This crate should remain platform-neutral.
