# Client Core

Platform- and UI-independent Rust logic for the Pigeon client.

Expected responsibilities include:

- identity and device management
- active/dormant/revoked device-state handling
- signed device-revocation events
- signed routing records and server migration
- encryption and decryption
- conversation and event state
- server communication
- per-device synchronization and acknowledgements
- configurable local history retention
- contacts and groups
- call and media signaling state

The client core must treat server changes as identity events rather than local-only settings. It must accept only newer valid signed routing revisions and automatically follow them when another authorized device has migrated the identity.

The client core must distinguish device authorization from delivery status. Dormant devices remain authorized and may reactivate automatically after reconnecting; revoked devices must not reactivate without explicit reauthorization.

Normal recent synchronization should come from the current Pigeon server. Long-term history remains local to devices or user-controlled backups.

This layer must not depend on Tauri so it can be reused across platforms and application shells.
