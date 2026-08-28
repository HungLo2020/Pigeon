# Client Core

Platform- and UI-independent Rust logic for the Pigeon client.

Expected responsibilities include:

- identity and device management
- encryption and decryption
- conversation and event state
- relay communication
- multi-device synchronization
- contacts and groups
- call and media signaling state

This layer must not depend on Tauri so it can be reused across platforms and application shells.
