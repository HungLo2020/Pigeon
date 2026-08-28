# Client Core

Platform- and UI-independent Rust logic for the Pigeon client.

Expected responsibilities include:

- cryptographic identity and device management
- encryption and decryption
- contact and conversation state
- signed routing-record creation and verification
- current-server selection and migration
- communication with local and remote Pigeon servers
- reliable message/event synchronization across authorized devices
- groups and community state
- call and media signaling state

The client core must treat the identity key as stable and server addresses as replaceable routing information.

This layer must not depend on Tauri so it can be reused across platforms and application shells.
