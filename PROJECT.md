# Pigeon Project Outline

## Problem

- Modern communication platforms usually bind identity, message history, discovery, and delivery to a provider-controlled account or server.
- Pure peer-to-peer systems can avoid that dependency but often become unreliable when mobile devices sleep, change networks, or sit behind NAT/CGNAT.
- Pigeon aims to keep user identity and communication sovereign while still providing reliable, practical delivery across real-world networks.

## Non-Negotiable Requirements

- No email address or phone number required.
- User identity is cryptographic and independent of any server or external platform.
- Multi-device support without allowing a server to own or recreate a user's identity.
- Direct text messaging.
- Group text messaging.
- Direct voice and video calls.
- Group voice and video calls.
- Discord-style communities with persistent text and voice channels.
- Live video and screen streaming.
- iOS and Linux support, with room for additional platforms.
- End-to-end encryption for messages, files, calls, streams, and group communication.
- All infrastructure is assumed hostile.
- Reliable offline message delivery.
- Operation across Wi-Fi, cellular, NAT, CGNAT, and changing networks.
- Server loss must not destroy user identities or already-delivered conversation history.

## Implementation Structure

- Rust is the primary implementation language.
- The repository should be organized as a Cargo workspace.
- Shared protocol, identity, cryptographic abstractions, serialization, event formats, and common types belong in `src/shared/`.
- The untrusted relay implementation belongs in `src/server/`.
- The cross-platform application belongs in `src/client/`.
- Platform-neutral client logic belongs in `src/client/core/` and must not depend on Tauri.
- Tauri-specific application lifecycle, commands, permissions, notifications, and OS integration belong in `src/client/tauri/`.
- Shared frontend code belongs in `src/client/frontend/`.
- Non-code assets belong in `resources/`.

## Architecture Principles

- Separate **identity** from **routing and delivery**.
- Represent each user with a long-lived cryptographic root identity.
- Give each device its own key authorized by the user's identity.
- Keep identity keys and delivered history on user devices.
- Make relay addresses and infrastructure replaceable.
- Use temporary encrypted mailboxes/queues for offline message delivery.
- Allow redundant relays so a single relay failure does not prevent delivery.
- Store only ciphertext on relay and blob-storage infrastructure.
- Use acknowledgements and eventual synchronization between user devices.
- Use well-reviewed cryptographic protocols rather than inventing new primitives.
- Evaluate MLS for encrypted asynchronous group state and messaging.
- Use direct peer-to-peer media when possible.
- Use STUN/ICE for NAT traversal and TURN when direct media paths fail.
- Use an SFU for scalable group calls and streaming while keeping media end-to-end encrypted.
- On iOS, use Apple push infrastructure only as a wake-up mechanism; message contents remain outside APNs.
- Keep core client behavior independent of Tauri and operating-system-specific APIs.

## Trust Model

- Relays are untrusted.
- TURN servers are untrusted.
- SFUs are untrusted.
- Blob/file servers are untrusted.
- Network operators are untrusted.
- Infrastructure compromise must not reveal plaintext communication or permit user impersonation.
- Infrastructure may learn unavoidable metadata such as IP addresses, timing, and traffic volume; minimizing this metadata is a design goal.

## Failure Model

- A user may be offline for hours or days and should still receive queued messages later.
- A phone may be suspended by the operating system and should recover cleanly after wake-up.
- A relay may disappear without warning.
- A self-hosted server may be permanently lost.
- Individual devices may be lost or revoked.
- Multiple devices may receive events in different orders and must converge on the same conversation state.

## Fundamental Invariant

- Deleting every Pigeon server should not delete a user's identity or already-delivered history.
- Replacing infrastructure should change where communication is routed, not who the user is.
