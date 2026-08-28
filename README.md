# Pigeon

Pigeon is a sovereign, end-to-end encrypted communication platform built around portable cryptographic identity rather than phone numbers, email addresses, or provider-owned accounts.

## Goals

- Direct text, voice, and video communication.
- Group messaging and group voice/video calls.
- Discord-style communities with persistent text and voice channels.
- Live video and screen streaming.
- iOS and Linux as primary client targets.
- End-to-end encryption for messages, files, calls, streams, and group communication.
- Reliable offline delivery across Wi-Fi, cellular, NAT, and CGNAT.
- User identities that remain valid when changing servers.
- Self-hosting without requiring every user to host infrastructure.
- No global authoritative Pigeon identity directory.

## Core Model

Pigeon separates **identity** from **routing**.

- A user's stable identity is a cryptographic public key.
- A server address is mutable routing metadata, not part of the identity.
- When sharing an identity, the user also shares a current server/routing hint.
- Contacts cache each other's current signed routing records.
- Routing records are versioned and signed by the identity owner.
- A user may move from one server to another without changing identity.
- Existing contacts learn moves through signed routing-update messages.
- An old server may temporarily return a signed migration/forwarding record when available.
- Servers coordinate delivery and synchronization for users currently using them, but cannot impersonate users or decrypt content.
- There is no requirement for one server to own a conversation or for all servers to replicate all conversation history.

## Server Role

Pigeon servers are operationally authoritative but cryptographically constrained.

They may manage:

- current device/routing state for connected users
- pending encrypted message delivery
- acknowledgements and offline queues
- presence and call signaling
- encrypted attachment transfer/storage as required
- TURN/SFU integration for media

They must not own:

- user identity keys
- plaintext messages or media
- authority to add devices without valid user authorization
- authority to silently rewrite signed routing state

## Technology and Repository Layout

- Pigeon is implemented primarily in Rust.
- The repository is intended to be a Cargo workspace.
- `src/shared/` contains platform-neutral protocol and shared library code.
- `src/server/` contains the Pigeon server implementation.
- `src/client/` contains the shared cross-platform client.
- `src/client/core/` contains UI- and platform-independent client logic.
- `src/client/tauri/` contains the Tauri application shell and platform integration.
- `src/client/frontend/` contains the shared frontend.
- `resources/` contains non-source assets such as icons and bundled imagery.

The client core must remain independent of Tauri so identity, cryptography, routing, messaging, synchronization, groups, and call logic can be reused across platforms.

## Status

Pigeon is currently in the architecture and protocol-design phase.

See [PROJECT.md](PROJECT.md) for the detailed project requirements and current architecture.
