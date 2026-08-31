# ADR 0007: Encrypted attachment delivery

## Status

Accepted.

## Decision

Attachments use a versioned, two-layer design. A sender generates a fresh
32-byte content key, 24-byte XChaCha20 nonce, and 32-byte attachment ID with
the operating-system CSPRNG for every attachment. It encrypts a canonical
plaintext containing the filename, MIME type, and bytes with
XChaCha20-Poly1305. The AEAD associated data binds the attachment ID and MLS
group ID. Plaintext and ciphertext SHA-256 hashes, byte count, and protocol
version are verified before an attachment is accepted.

The opaque ciphertext record sent to a relay contains only canonical sender
and recipient genesis selectors, explicit target devices, attachment ID, MLS
group ID, ciphertext length/hash, nonce, and ciphertext. Filename, MIME type,
and content key remain in an `AttachmentDescriptor` carried inside the
corresponding MLS application message. A descriptor cannot be accepted for a
different MLS group, attachment ID, ciphertext hash, or plaintext hash.

Relays store opaque ciphertext separately from MLS events. Their attachment
delivery rows are per active recipient device. They exclude revoked and
dormant devices from new targets; revoked/dormant devices stop blocking early
deletion. A relay deletes attachment ciphertext once every required active
device has fetched, verified, decrypted, and acknowledged it, and always no
later than 14 days. Cross-relay attachment forwarding uses the same pinned
TLS, relay Ed25519 signatures, durable outbound queue, and signed MOVED retry
rules as opaque MLS forwarding. A relay never sees an attachment key or
plaintext and has no authority to alter a descriptor.

On Linux, `pigeon-client-daemon` remains the only owner of upload, fetch,
decryption, cache writes, acknowledgements, retry, and state updates. Tauri
can submit a selected local path through typed IPC and request an explicit
save; it does not receive keys or independently perform attachment network or
cryptographic work. Received content is cached in a per-account private
directory (0700 directory, 0600 files). Filenames are validated as leaf names;
Pigeon never executes or automatically opens received files.

Portable identity backup and pairing bootstrap deliberately exclude decrypted
attachment bytes and attachment keys. They retain neither attachment content
nor an implicit history-transfer promise.

## Security invariants

1. Attachment encryption keys are random, per-attachment, and never derived
   from root, recovery, device, or long-lived MLS keys.
2. Only current MLS members/devices can obtain a descriptor/content key.
3. Relays hold opaque ciphertext and explicit delivery metadata only.
4. Ciphertext integrity, descriptor binding, group binding, and plaintext
   integrity are all checked before acknowledgement.
5. A duplicate attachment ID with different ciphertext is rejected; retries
   of the same opaque record are idempotent.
6. Local cache paths are not relay-provided paths and never permit traversal.

## Consequences

Attachment transfers are resumable through bounded relay storage but are not
long-term server archives. Downloads that fail integrity checks are not
acknowledged and remain retriable until the normal retention deadline.
