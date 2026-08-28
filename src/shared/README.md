# Shared Library

Shared Rust code used by both the Pigeon client and server.

Expected responsibilities include:

- protocol types and wire formats
- serialization and shared errors
- cryptographic identity abstractions
- device credentials and authorization records
- signed, versioned routing records
- server-migration records
- message, event, acknowledgement, and synchronization formats
- cross-server delivery protocol types
- group and call-signaling protocol types

This crate should remain platform-neutral and must not contain Tauri-specific behavior.
