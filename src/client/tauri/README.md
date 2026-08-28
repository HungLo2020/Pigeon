# Tauri Application

Tauri-specific application code for the Pigeon client.

Expected responsibilities include:

- application lifecycle
- frontend/backend commands
- permissions
- notifications and push integration
- window and platform integration
- iOS- and Linux-specific bridges where required
- exposing server-selection and migration workflows to the shared client core

Identity, cryptography, routing verification, messaging, synchronization, and protocol behavior must remain in the client core rather than this layer.
