# Client

The Pigeon client is shared across supported desktop and mobile platforms.

- `core/` contains platform-neutral client behavior.
- `tauri/` contains the Tauri application shell and platform integration.
- `frontend/` contains the shared user interface.

The client owns user keys, local long-term history, encryption/decryption, conversations, contacts, groups, retention settings, routing state, and call state.

Each authorized device synchronizes recent state independently with the user's current server when it connects. Normal synchronization must not depend on another user device being online.

Server changes are signed identity events. When one device changes servers, the client core must create and propagate a newer signed routing revision so the user's other devices and contacts can automatically follow the migration when they reconnect.

Local history retention should be independently configurable, initially including 30 days, 90 days, 1 year, 5 years, and forever.
