# Pigeon Project Outline

## Problem

- Modern messengers usually bind identity, routing, delivery, and history to one provider-controlled account or server.
- Pure peer-to-peer systems avoid that dependency but can become unreliable when devices sleep, change networks, or are offline.
- Pigeon aims to preserve user-owned identity and end-to-end encryption while still using servers strongly enough to provide reliable communication.

## Non-Negotiable Requirements

- No email address or phone number required.
- User identity is cryptographic and independent of any server or external platform.
- Users may choose or self-host a Pigeon server.
- Changing servers must not change identity.
- No global authoritative Pigeon identity directory.
- Multi-device support without allowing a server to own or recreate a user's identity.
- Direct and group text messaging.
- Direct and group voice/video calls.
- Discord-style communities with persistent text and voice channels.
- Live video and screen streaming.
- iOS and Linux support, with room for additional platforms.
- End-to-end encryption for messages, files, calls, streams, and group communication.
- Servers and network infrastructure are untrusted with respect to message/media contents and identity authority.
- Reliable offline message delivery.
- Operation across Wi-Fi, cellular, NAT, CGNAT, and changing networks.

## Identity and Routing

- A user's long-lived cryptographic public key is the stable public identity.
- Server location is separate, mutable routing metadata.
- A shared contact card/invitation carries both the stable identity and a current server/routing hint.
- The server address is never part of the identity itself.
- Contacts cache the latest verified routing record for each known identity.
- Routing records are signed by the identity owner and include a monotonically increasing revision/version.
- Clients reject unsigned, invalid, or stale routing changes.
- A user does not need to know another user's server until that user shares or sends valid routing information.

## Server Migration

- Moving from Server A to Server B must preserve the same cryptographic identity.
- The moving client creates a newer signed routing record pointing to Server B.
- Existing contacts receive the new record through normal Pigeon communication whenever possible.
- If Server A is still available, it may temporarily return or forward a signed migration record directing contacts to Server B.
- Contacts verify the identity signature and revision before replacing cached routing information.
- If the old server disappears unexpectedly, the moved user can proactively contact known peers through their cached routes and distribute the new signed record.
- Initial-contact or catastrophic-recovery cases may still require explicit out-of-band exchange; Pigeon should not introduce a central identity authority merely to eliminate that edge case.

## Server Responsibilities

A Pigeon server is authoritative for operational coordination while a user uses it, including:

- device registration state that is backed by valid user/device signatures
- current delivery routing for attached users/devices
- pending encrypted messages
- delivery acknowledgements and offline retention
- presence
- call and media signaling
- temporary or bounded encrypted blob/attachment storage
- abuse controls and resource limits
- media-relay integration such as TURN or SFU infrastructure

A Pigeon server is not authoritative for:

- the user's cryptographic identity
- private identity/device keys
- plaintext messages, files, calls, or streams
- adding devices without valid authorization
- changing a user's routing identity without a valid signed update

## Cross-Server Communication

- Servers are service providers, not identity owners.
- A conversation does not have to belong to one server.
- If Person X uses Server Y and Person Z uses Server A, each side communicates using the other participant's cached current route.
- Servers do not need to replicate every conversation or maintain one global canonical message database.
- Cross-server delivery should exchange only the coordination and encrypted payload data required for reliable communication.
- A user may run a private server for family/friends while still communicating with users on other Pigeon servers.

## Multi-Device Model

- A root identity authorizes individual device keys.
- Servers may coordinate currently authorized device state, but clients verify the underlying signatures.
- Messages should be delivered to the appropriate authorized devices rather than assuming one device represents the user.
- Outgoing events from one device must become visible to the user's other authorized devices through the normal synchronization/delivery model.
- Multiple devices may receive events in different orders and must converge deterministically.
- Historical-data migration to newly added devices is a separate concern from live message delivery and must not require making servers the permanent owner of plaintext history.

## Cryptography and Trust

- Use well-reviewed cryptographic protocols and primitives rather than inventing cryptography.
- Evaluate MLS for asynchronous encrypted group state and messaging.
- Infrastructure compromise must not reveal plaintext communication or permit user impersonation.
- Infrastructure may learn unavoidable metadata such as IP addresses, timing, routing relationships, and traffic volume; minimizing this metadata is a design goal.

## Calls and Media

- Prefer direct peer-to-peer media when possible.
- Use STUN/ICE for NAT traversal.
- Use TURN when direct media paths fail.
- Use an SFU for scalable group calls and streaming while preserving end-to-end media encryption.
- On iOS, Apple push infrastructure may be used only as a wake-up mechanism; message contents must remain outside APNs.

## Implementation Structure

- Rust is the primary implementation language.
- The repository should be organized as a Cargo workspace.
- Shared protocol, identity, signed-routing, cryptographic abstractions, serialization, event formats, and common types belong in `src/shared/`.
- The Pigeon server belongs in `src/server/`.
- The cross-platform application belongs in `src/client/`.
- Platform-neutral client logic belongs in `src/client/core/` and must not depend on Tauri.
- Tauri-specific application lifecycle, commands, permissions, notifications, and OS integration belong in `src/client/tauri/`.
- Shared frontend code belongs in `src/client/frontend/`.
- Non-code assets belong in `resources/`.

## Failure Model

- A user may be offline for hours or days and should still receive queued messages later.
- A phone may be suspended by the operating system and should recover cleanly after wake-up.
- A selected server may disappear without warning.
- A user may intentionally migrate to another server.
- Individual devices may be lost or revoked.
- Multiple devices may receive events in different orders and must converge on the same logical state.
- Server migration must never require changing the user's cryptographic identity.

## Fundamental Invariants

- **Identity is not a server address.**
- **Routing is mutable, signed state.**
- **Changing providers must not change who the user is.**
- **Servers may coordinate communication but may not become cryptographic identity authorities.**
- **No central Pigeon directory is required for normal communication between established contacts.**
