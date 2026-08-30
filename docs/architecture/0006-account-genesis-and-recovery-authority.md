# ADR 0006: Immutable account genesis and recovery-gated authority

## Status

Accepted.

## Decision

An account is anchored by a canonical, versioned `PigeonAccountGenesis`:
root public key, initial device public key/record, an independent recovery
public key, a CSPRNG genesis nonce, protocol version, and the initial public
display name.  The stable account ID is SHA-256 over a domain-separated
canonical encoding of that genesis. It is never the root public key itself.
Two different valid genesis records remain different accounts even if they
reuse a root key.

The root key signs public profile, routing, device records, and account-state
records, but root possession alone is insufficient to enroll a device into an
established account. The authenticated roster is an evolving, versioned chain
bound to genesis. A normal device-add transition requires all of:

- a root signature;
- a signature by the independent recovery authority; and
- a signature by a device in the preceding authorized roster.

Recovery from an encrypted portable backup is the only transition that may
replace the third requirement. It still requires root and recovery authority,
creates a new device credential, and is visibly marked as a recovery
transition. Relays verify public transition evidence but never learn a
password, recovery secret, root secret, device private key, MLS private state,
or message plaintext.

Recovery authority is a random Ed25519 secret generated from the operating
system CSPRNG. It is neither derived from the root key nor from the password.
Each device stores only an Argon2id (versioned parameters) + XChaCha20-Poly1305
wrapped copy of it. Changing a password authenticates with the old password
and rewraps the same recovery secret; genesis, account ID, roster authority,
and recovery public key do not change.

Portable backup is versioned and encrypted with the supplied password using
the same Argon2id and authenticated-encryption design. Its plaintext contains
genesis, root/recovery authority, signed public account/routing/roster and
revocation state, contacts, and non-device-specific control metadata. It never
contains another endpoint's device private credential, MLS signer/runtime
state, MLS epoch secrets, or long-term history. Import always creates a fresh
device and fresh MLS material and authorizes it through recovery.

Mutable display names remain root-signed profile metadata. Local nicknames are
account-local presentation data and never leave the device. Full account IDs
are used for all protocol comparisons; shortened IDs are presentation only.

## Migration and invariants

The prior root-key-as-ID state format is incompatible. Clients reject it with
a clear migration error; they must not infer a genesis or silently preserve a
root-only enrollment path. New relays reject conflicting genesis data for an
existing account ID and validate roster transitions against the prior roster.

1. Root-key possession alone cannot create a normal enrollment transition.
2. A device approval cannot be replayed against another account, genesis,
   roster revision, or recovery capability.
3. Recovery/password possession does not reveal historical MLS state absent a
   separately exported history/epoch transfer.
4. Relay storage and TLS/routing remain operational metadata, never account
   authority.

