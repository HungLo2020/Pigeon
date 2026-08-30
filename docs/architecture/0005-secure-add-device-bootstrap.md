# ADR 0005: Secure add-device authorization and bootstrap

## Status

Accepted.

## Context

Pigeon identities may have several independently authenticated device
endpoints. ADR 0001 requires MLS membership to contain device endpoints, and
ADR 0003 requires a physical device to be able to add a separate device to an
existing identity without making a relay the identity authority. The existing
identity backup is recovery material, not an ordinary device-pairing channel.

This decision defines the future add-device protocol. It does not change any
current wire format or implement pairing.

## Decision

### Roles and authority

- The **new device** creates its own long-lived Ed25519 device credential and
  MLS KeyPackage locally. It never reuses, imports, or clones another device's
  credential or MLS signer.
- Every authorized device is an equal peer: it holds the same root identity
  private key plus its own distinct device private key, `DeviceRecord`, MLS
  credential/KeyPackage, and local state. No device is a privileged master.
- An **approving device** is any already-authorized peer that signs the exact
  roster transition with its distinct device credential. Normal approval also
  requires the independent recovery authority unlocked by the account password.
- A **recovery authority** may create the distinct recovery transition after an
  encrypted backup import. Root authority by itself is never sufficient.
- A relay may store and forward opaque pairing artifacts, but it cannot create
  an approval, modify an artifact successfully, decrypt bootstrap data, or
  grant a device authority.

Normal pairing transfers equal-peer root authority only inside the matching
authenticated encrypted bootstrap. The root private key is never present in a
pairing request, QR code, copyable text, relay-visible record, or plaintext
approval. A device's separate private credential and MLS signer are never
copied to another device.

### Pairing request

The new device creates a single-use `PairingRequest` with:

- protocol version;
- stable random `session_id` and independent random nonce (at least 128 bits
  each);
- creation time and short expiry (implementation default: 10 minutes);
- target root identity fingerprint, when known;
- the new device's fresh public device key, its MLS KeyPackage, and the public
  fields required to construct its `DeviceRecord`;
- a fresh X25519 HPKE receiver public key for bootstrap encryption; and
- optional user-visible device display metadata, explicitly non-authoritative.

The request contains no root secret, account-state secret, conversation key,
MLS private state, or relay trust assertion. QR and copyable text are merely
canonical encodings of this exact public request; they have identical
validation rules and security properties.

The request is locally recorded by the new device as pending and is invalid
after cancellation, successful consumption, or expiry. A session ID is never
reused, including after restart.

### Relay artifact access

Relay artifacts use a versioned opaque envelope containing identity, session
ID, nonce, artifact kind, expiry, an access-capability commitment, and opaque
bytes. Requests may be fetched publicly by session ID. The bootstrap read
capability and a separate cancellation capability are random 256-bit values;
only their SHA-256 commitments appear in public artifacts. The new device
retains both secrets locally. Approval/bootstrap fetch-and-consume requires the
bootstrap capability and is atomic; a wrong capability reveals nothing and
does not consume. Cancellation requires the cancellation capability. The
bootstrap capability commitment is included in the root-signed approval
transcript, preventing substitution. Relays expose only the envelope metadata
and never decrypt payloads.

### Approval and roster update

The approving device verifies the request version, expiry, target identity,
nonce/session freshness, and the MLS KeyPackage before asking root authority
to create a `DeviceRecord`. The root signature covers the fresh device key and
KeyPackage through the existing `DeviceRecord` format.

The resulting `PairingApproval` is root-signed and its referenced roster also
binds recovery and authorized-device signatures in a canonical
versioned signed payload:

- root identity;
- pairing `session_id` and nonce;
- exact serialized new `DeviceRecord`;
- resulting `AuthorizedDeviceSet` revision and roster digest;
- expiry; and
- the hash of the paired bootstrap ciphertext/AAD transcript.

The approving device publishes the new root-signed roster/card through normal
identity synchronization before considering approval complete. A relay may
verify public signatures for routing/delivery only; it cannot substitute a
different device record, roster, nonce, or revision.

Approvals are accepted once only by the new device and once only by the
approving device's local pairing ledger. A device rejects an approval if any
bound field differs from its pending request, if it is expired/cancelled, if
the roster does not contain exactly the approved device record, or if its
identity/revision is invalid or stale.

### Encrypted bootstrap channel

Bootstrap data is sealed from the approving device to the request's fresh
X25519 receiver key using RFC 9180 HPKE protocol version 1 and the concrete
suite **DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM**. The
implementation must use a mature audited Rust HPKE implementation; it must
not construct a custom encryption scheme. The HPKE associated data is
the canonical approval binding (identity, session ID, nonce, exact device
record, roster revision/digest, expiry, and protocol version). The approval's
root signature authenticates that same binding.

The bootstrap ciphertext contains the equal-peer root private identity
material and the control state needed by the new device:

- root identity private key material;
- current signed `AuthorizedDeviceSet` and revocation set;
- current signed routing record and pending/cached valid routes;
- signed contact cards and contact routing cache;
- conversation/group identifiers and membership metadata;
- MLS Welcome and/or commit material required to add the new endpoint to
  existing direct and group conversations; and
- locally necessary non-secret configuration for synchronization.

It never includes existing device private credentials, existing MLS
signer/private state, or long-term history by default. Message history transfer
is a separate optional, explicitly initiated device-to-device history feature
and is not part of pairing. The new device may therefore have history gaps
outside retained relay content or a later user-controlled history transfer.

### MLS and delivery effects

After the roster update, the approving device updates each relevant direct and
ordinary-group MLS group by adding the new device's locally generated
KeyPackage. It sends the corresponding opaque MLS commits/Welcome material
through ordinary relay delivery with explicit target devices. Future content is
addressed to the new authorized device according to existing active/dormant,
revocation, ACK, and 14-day retention rules. Existing content is not promised
unless it remains within the normal relay window or is included by a separate
history transfer.

### Transport, cancellation, and recovery

Pairing request, approval, and encrypted bootstrap artifacts may use the
relay's bounded opaque delivery store. Relay persistence is transport-only:
artifacts have their own expiry and are deleted on successful consumption or
expiry. The relay need not and must not persist permanent pairing history.

- Either device may cancel an unconsumed session locally; cancellation records
  the session ID so later artifacts are rejected.
- An approving-device restart restores its pending/consumed/cancelled ledger
  and must not issue a second approval for the same session.
- A new-device restart restores its pending request and HPKE receiver private
  key only until expiry/cancellation; it must not generate replacement data
  under the same session ID.
- Relay loss or restart may delay transport but cannot change a signed
  approval. The devices may retry opaque artifacts until expiry.
- If approval was published but bootstrap delivery fails, the new device is
  authorized but remains unusable until a valid matching bootstrap is received
  or a user explicitly starts a new recovery/repair flow. The relay must not
  synthesize bootstrap state.

## Security invariants

1. Every paired device has a distinct locally generated long-lived device key
   and MLS KeyPackage.
2. Only root authority creates a valid `DeviceRecord` or roster update.
3. Approval binds exactly one identity, session, nonce, device record, roster
   revision, and encrypted bootstrap transcript.
4. A pairing request or approval is single-use, short-lived, cancellable, and
   replay-resistant across restart.
5. QR/copyable pairing text contains public request data only.
6. Relay compromise cannot reveal bootstrap state, root secrets, MLS private
   state, or create a valid authorization.
7. Pairing does not silently grant root private-key possession or clone an
   existing device credential.
8. Revoked devices remain unable to reactivate or receive future delivery;
   pairing a replacement requires a fresh device record and normal approval.
9. Ordinary device revocation cannot erase root identity material already
   copied to that device. Suspected root-key extraction is a catastrophic
   identity compromise and requires a separate future recovery/key-rotation
   mechanism; it is not repaired by revoking a device credential.

## Implementation and test plan

1. Add versioned shared protocol types for request, approval, opaque artifact
   transport, and persistent pairing-ledger state. Reject unknown/legacy
   versions rather than guessing.
2. Add core-only request generation, approval, HPKE sealing/opening, roster
   publication, and MLS endpoint-add services. Tauri exposes typed commands;
   frontend renders state only.
3. Add relay storage solely for expiring opaque pairing artifacts and consumed
   identifiers; it must not decrypt or approve them.
4. Add GUI QR/copyable request presentation, explicit approval confirmation,
   waiting/approved/failed/expired/cancelled states, and recovery guidance.
5. Test successful two-device authorization, forged/identity-mismatched
   approval rejection, altered bootstrap rejection, replay and cancellation,
   expiry, device/relay restart persistence, roster propagation, and future
   direct/group MLS delivery to both devices.
6. Test that neither a relay nor QR/copyable text gains root authority or
   plaintext/history access, and that root private material is transferred
   only inside a valid HPKE bootstrap or explicit backup import.

## Consequences

Pairing is an explicit asynchronous protocol with durable local session state,
not a shortcut around root authority. It gives the product a QR-friendly path
for adding endpoints while preserving Pigeon's separation of identity,
routing, relay delivery, MLS state, and optional long-term history.
