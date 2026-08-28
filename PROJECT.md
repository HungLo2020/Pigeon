# Pigeon Project Outline

## Problem

- Existing communication systems commonly bind identity, routing, history, and service ownership together.
- Pure peer-to-peer systems can avoid central ownership but often become unreliable when devices sleep, change networks, or are offline.
- Pigeon aims to keep identity and long-term history user-owned while allowing servers to provide reliable coordination and recent synchronization.

## Non-Negotiable Requirements

- No email address or phone number required.
- User identity is cryptographic and independent of any server or external platform.
- Multi-device support without allowing a server to own or recreate a user's identity.
- Direct and group text messaging.
- Direct and group voice/video calls.
- Discord-style communities with persistent text and voice channels.
- Live video and screen streaming.
- iOS and Linux support, with room for additional platforms.
- End-to-end encryption for messages, files, calls, streams, and group communication.
- Infrastructure is assumed hostile.
- Reliable offline delivery and multi-device synchronization.
- Operation across Wi-Fi, cellular, NAT, CGNAT, and changing networks.
- Server loss must not destroy a user's identity or already-retained device history.

## Identity and Routing

- A user's stable identity is a long-lived cryptographic identity key.
- The server currently used by that identity is routing metadata, not part of the identity itself.
- Public contact information carries the identity plus a current server hint.
- Once contact is established, each side caches the latest valid signed routing record for the other identity.
- Routing records are signed by the identity and monotonically versioned.
- Clients reject unsigned, invalid, or older routing revisions.
- No global authoritative Pigeon directory is required.

## Server Changes

- Changing servers is an identity-level event, not a local-only preference.
- A server migration produces a new signed routing record with a higher revision.
- The initiating device should register with the new server first, then publish the signed migration through the old server when available.
- The old server may temporarily return a signed `MOVED`/migration record directing contacts and other devices to the new server.
- Other authorized devices automatically switch when they receive a newer valid routing revision.
- Existing contacts should receive and cache the newer signed route through normal communication paths.
- If the old server is unavailable, the migration remains valid: the initiating device queues the signed migration and propagates it through any reachable contact/server path.
- A server change is not considered fully propagated until the user's reachable devices and active contacts have had an opportunity to learn the newer revision.
- Devices that were offline may retain a stale route until they receive a newer signed revision; once received, they must switch automatically.
- If every previously known route is unavailable and neither side has any surviving communication path, out-of-band re-contact may be required. Pigeon must not solve this by introducing a central authoritative identity directory.

## Server Retention

- Servers store encrypted content only as a bounded synchronization/delivery window.
- Content is retained for at most **14 days**, or until it has been delivered to **all currently authorized devices for the relevant identities**, whichever happens first.
- Delivery acknowledgements are tracked per authorized device.
- Revoked devices no longer block deletion.
- Server-side long-term conversation archives are not part of the architecture.
- Small current control state needed for operation may persist while an identity uses the server, including authorized-device state, current routing revision, public device credentials, and delivery bookkeeping.

## Device Retention

- Devices hold the user's long-term conversation history.
- Local retention is configurable independently of the server window.
- Initial retention options should include approximately:
  - 30 days
  - 90 days
  - 1 year
  - 5 years
  - forever
- A device offline for less than the server retention window should be able to catch up entirely from the server.
- A device offline beyond the server retention window may have a history gap unless another authorized device or user-controlled backup can supply it.

## Multi-Device Synchronization

- The server is authoritative for recent delivery state and recent encrypted synchronization data.
- Each authorized device independently synchronizes with the server when it connects.
- Devices do not depend on one another being online for normal recent synchronization.
- Identity events such as adding/removing devices and changing servers are synchronized through the same mechanism.
- Multiple devices may receive events in different orders but must converge on the same valid state.

## Implementation Structure

- Rust is the primary implementation language.
- The repository should be organized as a Cargo workspace.
- Shared protocol, identity, cryptographic abstractions, serialization, routing records, event formats, and common types belong in `src/shared/`.
- The server implementation belongs in `src/server/`.
- The cross-platform application belongs in `src/client/`.
- Platform-neutral client logic belongs in `src/client/core/` and must not depend on Tauri.
- Tauri-specific application lifecycle, commands, permissions, notifications, and OS integration belong in `src/client/tauri/`.
- Shared frontend code belongs in `src/client/frontend/`.
- Non-code assets belong in `resources/`.

## Architecture Principles

- Separate **identity** from **routing**.
- Separate **recent server synchronization** from **long-term device history**.
- Represent each user with a long-lived cryptographic root identity.
- Give each device its own key authorized by the user's identity.
- Treat server routing as signed, replaceable metadata.
- Let servers coordinate delivery and recent synchronization without making them permanent conversation archives.
- Use well-reviewed cryptographic protocols rather than inventing new primitives.
- Evaluate MLS for encrypted asynchronous group state and messaging.
- Use direct peer-to-peer media when practical.
- Use STUN/ICE for NAT traversal and TURN when direct media paths fail.
- Use an SFU for scalable group calls and streaming while keeping media end-to-end encrypted.
- On iOS, use Apple push infrastructure only as a wake-up mechanism; message contents remain outside APNs.
- Keep core client behavior independent of Tauri and operating-system-specific APIs.

## Trust Model

- Pigeon servers are operationally authoritative for recent delivery and synchronization, but cryptographically subordinate to user identities.
- Servers cannot create valid identity, device, or migration records without the appropriate user signatures.
- TURN servers, SFUs, storage paths, and network operators are untrusted.
- Infrastructure compromise must not reveal plaintext communication or permit user impersonation.
- Infrastructure may learn unavoidable metadata such as IP addresses, timing, server choice, and traffic volume; minimizing this metadata is a design goal.

## Fundamental Invariants

- Identity is not a server address.
- Changing servers does not change who the user is.
- A server stores only a bounded recent content window, not the user's permanent communication archive.
- Long-term history belongs to user devices and user-controlled backups.
- A newer valid signed routing revision always supersedes an older one.
