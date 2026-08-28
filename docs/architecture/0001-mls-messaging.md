# ADR 0001: MLS for encrypted conversation state

## Status

Accepted.

## Decision

Pigeon will use Messaging Layer Security (MLS) as the primary end-to-end
encryption protocol for conversation state.

- A direct conversation is an MLS group containing the authorized devices of
  the two participating identities.
- Group chats, private groups, and encrypted community channels are MLS
  groups with their authorized member devices as members.
- Pigeon root identities authorize device credentials. MLS credentials must be
  validated against those signed device records; a Pigeon server cannot create
  a valid device credential by itself.
- Servers act as untrusted delivery services for encrypted MLS messages and
  published key packages. They do not hold conversation keys or permanent
  plaintext history.
- MLS exporter secrets may coordinate keys for calls and streams, but media is
  encrypted separately in its WebRTC media path.

## Rationale

Pigeon requires asynchronous, end-to-end encrypted conversations spanning
multiple devices, direct chats, groups, and large persistent communities.
MLS provides forward secrecy and post-compromise security while handling
membership changes efficiently. Using it for both direct and group
conversations avoids maintaining separate bespoke cryptographic state machines
for pairwise and group messaging.

## Enrollment and recovery

New devices are authorized by an existing authorized device, normally through
a QR transfer or explicit approval. A user-controlled identity backup may be
imported when no existing device is available; it is not a
server-held password or account-reset mechanism.

## Consequences

- The protocol design must define the binding between Pigeon identity/device
  records and MLS credentials.
- Every membership, device authorization, revocation, and migration flow must
  specify its MLS group-state effect.
- Pigeon must use a mature, audited MLS implementation rather than implement
  MLS or ratcheting primitives itself.

## References

- RFC 9420, Messaging Layer Security (MLS)
