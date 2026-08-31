# Client

The Pigeon client is shared across supported desktop and mobile platforms.

- `core/` contains platform-neutral client behavior.
- `tauri/` contains the Tauri application shell and platform integration.
- `frontend/` contains the shared user interface.

The client owns user keys, local long-term history, encryption/decryption, conversations, contacts, groups, retention settings, routing state, device-management actions, and call state.

Each authorized device synchronizes recent state independently with the user's current server when it connects. Normal synchronization must not depend on another user device being online.

Clients must expose device-management controls that distinguish active, dormant, and revoked devices. A user may explicitly revoke a lost, stolen, retired, or unwanted device. A device inactive for more than 90 days becomes dormant rather than revoked and may become active again automatically when it reconnects with its still-valid credential.

Server changes are signed identity events. When one device changes servers, the client core must create and propagate a newer signed routing revision so the user's other devices and contacts can automatically follow the migration when they reconnect.

Relay setup accepts `host:port`, a hostname, or an explicit HTTPS descriptor
URL. Hostnames use `https://host/.well-known/pigeon-relay`; direct endpoints
display their relay/TLS fingerprints for explicit first-contact confirmation.
After confirmation, normal connections use only the persisted signed relay and
TLS-SPKI pins.

Local history retention should be independently configurable, initially including 30 days, 90 days, 1 year, 5 years, and forever.

## Linux desktop runtime

`daemon/` is the Linux desktop owner of live account state. It serializes core
operations, background sync, and history writes over a same-user Unix socket.
The Tauri host consumes typed snapshots/events and does not directly read or
mutate account files. Mobile hosts reuse core runtime behavior but are not
required to use Unix IPC or systemd.
