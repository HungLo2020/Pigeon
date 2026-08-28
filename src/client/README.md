# Client

The Pigeon client is shared across supported desktop and mobile platforms.

- `core/` contains platform-neutral client behavior.
- `tauri/` contains the Tauri application shell and platform integration.
- `frontend/` contains the shared user interface.

The client owns user keys, local state, encryption/decryption, synchronization, conversations, contacts, groups, and call state.
