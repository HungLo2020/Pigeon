# ADR 0002: Sovereign identity and peer-discovered routing

## Status

Accepted.

## Decision

Pigeon identity is an immutable versioned account genesis owned by the user,
not by a server, phone number, email provider, directory, or username service.

- The root identity key signs records, but the stable account ID is derived
  from canonical genesis rather than the root key. Established-account device
  enrollment additionally requires recovery authority and an authorized-device
  approval; root-key possession alone is not takeover authority.
- Users must be able to export a password-encrypted portable backup containing
  root and independent recovery material and restore it in order to regain control of their
  Pigeon identity after device loss.
- Restoring creates a fresh device through the recovery transition. It does not guarantee reconstruction of
  message history outside retained local history, a user-controlled backup, or
  the server's bounded synchronization window.
- New devices are normally authorized by QR transfer or approval from an
  existing authorized device plus password-unlocked recovery authority.
  Importing an encrypted identity backup is a fallback when no such device is
  available; it performs the distinct recovery authorization transition.

## No bootstrap directory

Pigeon has no global bootstrap, registration, or authoritative identity
directory.

1. A user may install and operate a Pigeon server on any reachable host.
2. During client setup, the user creates an identity locally, enters a chosen
   server address, and the client verifies that it can connect to that server.
3. The user publishes a signed routing record naming that server as current
   routing metadata for their identity.
4. Contacts exchange a signed contact card carrying the public identity
   information and current signed routing record. A QR code is one convenient
   representation of that card.
5. A contact using a different server follows the same QR exchange flow. No
   central service is consulted merely because the contacts use different
   servers.

The contact-card payload must be self-authenticating: the routing record is
signed by the identity key, versioned monotonically, and validated by the
receiving client before use. The same signed payload can be encoded as a QR
code, copyable URI/text, shareable contact file, or another transport-safe
representation. A server address in a contact card is a routing hint, not
proof that the server owns the identity.

## Trust boundary

Every Pigeon server is assumed hostile, including a server selected by the
identity owner.

Servers may route encrypted content, publish recent routing/device metadata,
and provide availability. They must not be able to:

- create or take over an identity;
- add, revoke, or recover a device without identity authorization;
- forge a signed routing record;
- read end-to-end encrypted content; or
- become the permanent canonical source of history.

## Conversation ownership

- A group chat is a peer conversation. It has no permanent owner; membership
  changes are governed by the group's encrypted protocol state and agreed
  group policy.
- A community is a distinct, Discord-like construct with an owner and
  delegated administrative/moderation roles. Its governance state, channel
  membership, and authorization rules are separate from ordinary group-chat
  semantics.

## Consequences

- The protocol must define a portable identity-backup format for root identity
  material and make clear that it is not server-side account recovery. Export
  must not require a passphrase; users must be warned that possessing the
  backup grants full identity authority.
- Signed contact-card format, its QR/text/file encodings, server-address
  validation, and key-change warnings are first-class protocol features.
- Cross-server communication is the normal case, not federation through a
  central registry.
- Community authorization needs its own design record; it must not be modeled
  as a group chat with an arbitrary privileged member.
