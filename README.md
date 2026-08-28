# Pigeon

Pigeon is a sovereign, end-to-end encrypted communication platform designed so that users—not servers, phone numbers, email providers, or third-party accounts—own their identities and long-term communication history.

## Goals

- Direct text messaging and voice/video calls.
- Group text messaging and group voice/video calls.
- Discord-style communities with persistent text and voice channels.
- Live video and screen streaming.
- iOS and Linux as primary platforms, with room for others.
- Cryptographic identities instead of phone numbers, email addresses, or provider-owned usernames.
- End-to-end encryption for messages, files, calls, streams, and group communication.
- Infrastructure is untrusted and must not be able to impersonate users or decrypt communication.
- Reliable server-backed synchronization without making the server the permanent owner of conversation history.

## Core Model

Pigeon separates **identity**, **routing**, **recent synchronization**, and **long-term history**.

- A user's identity is a stable cryptographic identity and is not tied to a server.
- A user's current server is mutable signed routing metadata.
- Contacts cache the latest valid signed routing record they have seen for each identity.
- Servers coordinate delivery, device synchronization, presence, signaling, and recent encrypted content.
- Servers retain content for at most 14 days, or until it has been delivered to all currently authorized devices for the relevant identities, whichever happens first.
- Devices retain long-term history according to local user-configurable retention policies.
- Server changes are signed identity events and should automatically propagate to the user's other devices and contacts.
- There is no global authoritative Pigeon identity directory.

## Device Retention

Individual devices should support configurable local history retention, with options such as:

- 30 days
- 90 days
- 1 year
- 5 years
- forever

Server retention is intentionally much shorter than device retention.

## Technology and Repository Layout

- Pigeon is implemented primarily in Rust.
- The repository is intended to be a Cargo workspace.
- `src/shared/` contains platform-neutral protocol and shared library code used by both client and server.
- `src/server/` contains the Pigeon server implementation.
- `src/client/` contains the shared client implementation.
- `src/client/core/` contains UI- and platform-independent client logic.
- `src/client/tauri/` contains the Tauri application shell and platform integration.
- `src/client/frontend/` contains the shared Tauri frontend.
- `resources/` contains non-source assets such as icons and bundled imagery.

The client core should remain independent of Tauri so communication, identity, cryptography, synchronization, retention, and protocol logic can be reused across platforms.

## Status

Pigeon is currently in the architecture and protocol-design phase.

See [PROJECT.md](PROJECT.md) for the project requirements and architecture.
