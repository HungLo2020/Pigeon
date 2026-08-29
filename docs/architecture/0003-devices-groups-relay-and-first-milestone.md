# ADR 0003: Devices, ownerless groups, hostile relay, and first milestone

## Status

Accepted.

## Identity backup and accounts on devices

- An identity backup is portable cryptographic identity material, not a
  password-derived server account.
- Exporting it must not require a passphrase. The client should strongly
  recommend that a user export it immediately after identity creation and
  store it in a safe, secure location.
- Importing an identity backup on a new device immediately grants that device
  authority to act for the restored identity and authorizes the device under
  that identity.
- The imported identity includes its current server routing information; setup
  connects the restored account to that server.
- A physical device may host multiple independent Pigeon accounts. Each
  account has its own root identity, device authorization, server-routing
  state, contacts, and local history. A server is selected by an identity /
  account, never as a device-wide setting; importing one account must not
  change the server used by another account already present on that device.

The backup is equivalent to possession of the root authority. The product must
make this consequence clear without requiring a passphrase for export.

Authorized devices are equal peers: each holds the root identity private key
and a distinct device credential. Revoking a device removes its credential
from the current roster and delivery/MLS state, but cannot erase root material
already copied to it. Root-key compromise therefore requires a separate future
recovery/key-rotation protocol.

## Multi-device conversation model

For MLS purposes, each authorized device is an independently authenticated
endpoint. A conversation is addressed to the current authorized devices of its
participating identities. This is a protocol-model statement, not a user
interface concept: users interact with people and accounts, not a visible list
of cryptographic leaves.

Device addition, device revocation, and recovery-driven device authorization
must update the relevant encrypted conversation membership and key state.

## Ordinary group chats

Ordinary group chats follow the iMessage-style model:

- no owner, administrator, or moderator role;
- any current participant may add or remove any participant; and
- the UI must not introduce consent or governance workflows for ordinary
  group-chat membership changes.

This policy is distinct from community governance.

## Communities

A community is a distinct Discord-like object with an owner and delegated
roles. Its ownership must be cryptographically bound to an identity, not to a
server. Community governance, migration, channel membership, and encrypted
channel state remain an open architecture decision.

## Cross-server delivery

The normal encrypted message path is:

`sender device -> sender server -> recipient server -> recipient device`

Servers relay opaque encrypted envelopes and recent synchronization data. Both
servers are hostile: neither may read message contents, forge identity/device
authority, or become a canonical history store. Recipients validate signed
identity, device, and routing records rather than relying on either server's
assertions.

## First milestone

The first implementation milestone is a secure vertical slice, not a
cryptographic prototype:

1. A user can set up and run a Pigeon server.
2. The server and two isolated client instances can run as three separate
   processes on the same development machine. Each client instance creates a
   separate identity, connects its own account to the server, exchanges a
   verified contact card, and sends end-to-end encrypted messages.
3. Contact exchange supports intended user-facing encodings from the outset:
   QR scanning plus copyable contact text/link. A developer-only contact
   import path is not the milestone target.
4. The milestone uses the intended identity, device authorization, encrypted
   delivery, and protocol architecture from the beginning. It must not weaken
   or replace those properties merely to reach the milestone sooner.

Running every process locally is a development topology, not an architectural
shortcut. Client/server communication must still use the same explicit network
protocol, persistent account state must remain isolated per client instance,
and no local-process trust, shared memory, shared private keys, or filesystem
assumption may be introduced that would prevent the instances from later being
run on different devices and networks.

The local topology must use the real authenticated encrypted transport from
the outset. Binding to a loopback address is allowed for development, but raw
HTTP, implicit localhost trust, and an alternate local-only protocol are not.

Communities, calls, streaming, cross-server routing, and broader product UI
may follow after this slice, but the cryptographic and protocol foundation must
not be a throwaway implementation.
