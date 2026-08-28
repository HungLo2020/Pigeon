# Pigeon

Pigeon is a sovereign, end-to-end encrypted communication platform designed so that users—not servers, phone numbers, email providers, or third-party accounts—own their identities and communication history.

## Goals

- Support direct text messaging and voice/video calls.
- Support group text messaging and group voice/video calls.
- Support Discord-style communities with persistent text channels and voice channels.
- Support live video and screen streaming.
- Run on mobile and desktop platforms, with iOS and Linux as primary targets.
- Use cryptographic identities instead of phone numbers, email addresses, or provider-owned usernames.
- End-to-end encrypt message contents, files, calls, streams, and group communication.
- Treat every relay, server, mailbox, TURN server, SFU, and network path as untrusted and potentially hostile.
- Keep identity ownership and delivered conversation history on user devices rather than on infrastructure.
- Remain usable across arbitrary networks, including Wi-Fi, cellular, NAT, and carrier-grade NAT.
- Provide reliable offline message delivery without requiring always-online peer-to-peer devices.

## Core Principle

Pigeon separates **ownership** from **delivery**.

- Identities belong to users and are represented cryptographically.
- Devices hold identity and device keys.
- Servers provide replaceable services such as temporary message queues, encrypted blob storage, NAT traversal, and media forwarding.
- Infrastructure must not be able to impersonate users or decrypt communication.
- Losing a relay or self-hosted server must not destroy a user's identity or already-delivered history.

## Technology and Repository Layout

- Pigeon is implemented primarily in Rust.
- The repository is intended to be a Cargo workspace.
- `src/shared/` contains platform-neutral protocol and shared library code used by both client and relay.
- `src/server/` contains the untrusted relay/server implementation.
- `src/client/` contains the shared client implementation.
- `src/client/core/` contains UI- and platform-independent client logic.
- `src/client/tauri/` contains the Tauri application shell and platform integration.
- `src/client/frontend/` contains the shared Tauri frontend.
- `resources/` contains non-source assets such as icons and bundled imagery.

The client core should remain independent of Tauri so the communication, identity, cryptography, synchronization, and protocol logic can be reused across platforms without being tied to a specific UI framework.

## Status

Pigeon is currently in the architecture and protocol-design phase.

See [PROJECT.md](PROJECT.md) for the project requirements and proposed architecture.
