# Client

The Pigeon client is shared across supported desktop and mobile platforms.

- `core/` contains platform-neutral client behavior.
- `tauri/` contains the Tauri application shell and platform integration.
- `frontend/` contains the shared user interface.

The client owns identity authority, private keys, encryption/decryption, local conversation state, contacts, groups, server selection, routing verification, server migration, synchronization, and call state.

A server may coordinate delivery, but the client must independently verify signed identity, device, and routing state.
