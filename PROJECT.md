# Pigeon Project Outline

## Problem

- Existing communication systems commonly bind identity, routing, history, and service ownership together.
- Pure peer-to-peer systems can avoid central ownership but often become unreliable when devices sleep, change networks, or are offline.
- Pigeon aims to keep identity and long-term history user-owned while allowing servers to provide reliable coordination and recent synchronization.

## Non-Negotiable Requirements

- No email address or phone number required.
- User identity is cryptographic and independent of any server or external platform.
- Users can export and import a password-encrypted portable recovery backup to
  restore authority on a fresh device after device loss without cloning an old
  device or MLS runtime.
- Multi-device support without allowing a server to own or recreate a user's identity.
- Direct and group text messaging.
- Ordinary group chats are ownerless: any participant may add or remove any
  participant, without administrator or consent workflows.
- Discord-style communities are distinct owner-governed objects and must not
  be treated as ordinary group chats.
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

- A user's authoritative stable identity is the complete canonical immutable,
  versioned account genesis record. Its SHA-256 `identity_id` is only a compact
  non-unique lookup/display/index value, never sufficient evidence that two
  accounts are the same and not a root public key.
- Every authorized device is an equal peer with a distinct device credential.
  Root signatures remain necessary but root-key possession alone cannot enroll
  an endpoint into an established account: normal enrollment also requires an
  existing-device approval and password-unlocked independent recovery authority.
- The server currently used by that identity is routing metadata, not part of the identity itself.
- Public contact information carries the identity plus a current server hint.
- A signed contact card is the canonical public-contact payload. QR codes,
  copyable links/text, and shareable files are alternate encodings of the same
  self-authenticating card.
- Once contact is established, each side caches the latest valid signed routing record for the other identity.
- Routing records are signed by the identity and monotonically versioned.
- Clients reject unsigned, invalid, or older routing revisions.
- No global authoritative Pigeon directory is required.
- Every authorization, transition, routing/delivery lookup, pairing session,
  contact map, MLS association, and relay row must bind/select canonical
  genesis. Relays may host multiple distinct accounts with the same compact
  ID; disconnected relays need no global collision awareness.

## Device Lifecycle

Every device associated with an identity is represented by an identity-authorized device credential and has one of three operational states.

A physical device may host multiple independent Pigeon identities/accounts.
Each account has independent identity authority, server routing, contacts, and
local history.

### Active

- The device remains cryptographically authorized.
- The server treats it as a current delivery target.
- Applicable content must remain available for that device until it acknowledges delivery or the content reaches the 14-day server maximum.
- A device that has been unused for days or weeks remains active until the 90-day inactivity threshold is reached or the user explicitly revokes it.

### Dormant

- An authorized device becomes dormant after more than **90 days** without activity.
- Dormancy is an operational delivery state, not cryptographic revocation.
- Dormant devices do not block early server deletion and are not included as required delivery targets for new content.
- The server may mark a device dormant based on observed inactivity, but it may not remove that device's authorization from the identity.
- When a dormant device reconnects, proves its still-valid device credential, and resumes use, it becomes active again automatically.
- A returning dormant device may have history gaps because content outside the server's 14-day synchronization window may no longer exist on infrastructure.

### Revoked

- Revocation is an explicit user-authorized identity change.
- The account/device-management UI must allow a user to view associated devices and revoke lost, stolen, retired, or unwanted devices.
- A revoked device immediately stops being a required delivery target and no longer blocks deletion.
- Future communication must not be delivered to a revoked device.
- A revoked device cannot simply reactivate itself by reconnecting; it must be explicitly re-added to the identity through the normal device-authorization process.
- Servers must never revoke devices from an identity on their own.
- Revocation removes the device credential from the current authorized roster,
  MLS memberships, and future delivery targets. It cannot erase root identity
  material that was previously copied to that device. Extracted root material
  is a catastrophic identity compromise requiring a separate future
  recovery/key-rotation protocol, not ordinary device revocation.

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
- Content is retained for at most **14 days**, or until it has been delivered to **all active authorized devices for the relevant identities**, whichever happens first.
- The 14-day limit is a hard maximum for ordinary content even if an active device remains offline and has not acknowledged delivery.
- Delivery acknowledgements are tracked per active authorized device.
- Devices that become dormant or are revoked stop blocking early deletion.
- A device that has merely been inactive for less than 90 days remains active and therefore still participates in delivery-completion decisions.
- Server-side long-term conversation archives are not part of the architecture.
- Small current control state needed for operation may persist while an identity uses the server, including authorized-device records, device state, last-seen timestamps, current routing revision, public device credentials, and delivery bookkeeping.
- Control state is not subject to the same 14-day deletion rule as ordinary communication content when retaining current state is required for correct operation.

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
- A dormant device returning after more than 90 days may rejoin automatically if it was never revoked, but should not expect infrastructure to reconstruct content older than the retained server window.

## Multi-Device Synchronization

- The server is authoritative for recent delivery state and recent encrypted synchronization data.
- Each active authorized device independently synchronizes with the server when it connects.
- Devices do not depend on one another being online for normal recent synchronization.
- Identity events such as adding/removing devices and changing servers are synchronized through the same mechanism.
- Device-state changes between active and dormant must propagate as operational state so all current clients can display a consistent device list.
- Explicit device revocations are signed identity events and must propagate to servers, the user's other devices, contacts, and group state wherever necessary to stop future delivery to the revoked credential.
- Multiple devices may receive events in different orders but must converge on the same valid state.

## Account / Device Management

- Each client should expose an account/device-management page.
- The page should show every known device associated with the identity.
- At minimum it should show device name/type, current state, and last activity when available.
- Users must be able to explicitly revoke a device from this interface.
- The UI should clearly distinguish active, dormant, and revoked devices.
- Dormancy must be reversible by reconnecting with the still-valid credential; revocation must not be reversible without explicit reauthorization.

## Implementation Structure

- Rust is the primary implementation language.
- The repository should be organized as a Cargo workspace.
- Shared protocol, identity, cryptographic abstractions, serialization, routing records, device-state records, event formats, and common types belong in `src/shared/`.
- The server implementation belongs in `src/server/`.
- The cross-platform application belongs in `src/client/`.
- Platform-neutral client logic belongs in `src/client/core/` and must not depend on Tauri.
- Tauri-specific application lifecycle, commands, permissions, notifications, and OS integration belong in `src/client/tauri/`.
- Shared frontend code belongs in `src/client/frontend/`.
- Non-code assets belong in `resources/`.

## Architecture Principles

- Separate **identity** from **routing**.
- Separate **authorization** from **delivery status**.
- Separate **recent server synchronization** from **long-term device history**.
- Represent each user with a long-lived cryptographic root identity.
- Give each device its own key authorized by the user's identity.
- Treat active/dormant status as server-observed operational state, while treating revocation as user-authorized cryptographic identity state.
- Treat server routing as signed, replaceable metadata.
- Let servers coordinate delivery and recent synchronization without making them permanent conversation archives.
- Use well-reviewed cryptographic protocols rather than inventing new primitives.
- Evaluate MLS for encrypted asynchronous group state and messaging.
- Use MLS as the primary encrypted conversation-state protocol for direct
  conversations, groups, and encrypted community channels.
- Use direct peer-to-peer media when practical.
- Use STUN/ICE for NAT traversal and TURN when direct media paths fail.
- Use an SFU for scalable group calls and streaming while keeping media end-to-end encrypted.
- On iOS, use Apple push infrastructure only as a wake-up mechanism; message contents remain outside APNs.
- Keep core client behavior independent of Tauri and operating-system-specific APIs.

## Trust Model

- Pigeon servers are operationally authoritative for recent delivery, synchronization, last-seen observations, and active/dormant status, but cryptographically subordinate to user identities.
- Servers cannot create valid identity, device-authorization, device-revocation, or migration records without the appropriate user signatures.
- A server may stop treating a device as an active delivery target after the protocol-defined inactivity period, but it cannot remove that device's cryptographic authorization.
- TURN servers, SFUs, storage paths, and network operators are untrusted.
- Infrastructure compromise must not reveal plaintext communication or permit user impersonation.
- Infrastructure may learn unavoidable metadata such as IP addresses, timing, server choice, device activity, and traffic volume; minimizing this metadata is a design goal.

## Fundamental Invariants

- Identity is not a server address.
- Changing servers does not change who the user is.
- Device authorization is not the same thing as active delivery status.
- More than 90 days of inactivity may make a device dormant, but only an authorized user action may revoke it.
- A server stores ordinary content only for a bounded maximum of 14 days and may delete it sooner once every active authorized target has acknowledged delivery.
- Long-term history belongs to user devices and user-controlled backups.
- A newer valid signed routing revision always supersedes an older one.
