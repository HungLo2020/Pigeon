# ADR 0004: Relay identity and authenticated cross-relay forwarding

## Status

Accepted.

## Decision

Each relay has a long-lived Ed25519 relay identity key. It is independent of
the relay's TLS certificate: TLS encrypts the connection, while the Pigeon
protocol signature authenticates the forwarding relay. No central relay PKI or
directory is required.

A root-signed, versioned `RoutingRecord` binds one routing tuple: an identity's
current network address, destination relay Ed25519 public-key fingerprint, and
the SHA-256 fingerprint of the relay TLS certificate's DER
`SubjectPublicKeyInfo` (SPKI). The root identity, not either relay, authorizes
the complete tuple. Relay and TLS identity are deliberately separate: relay
signatures authenticate forwarding envelopes, while the signed SPKI pin
authenticates the encrypted relay-to-relay connection. There is no central CA,
relay directory, TOFU cache, certificate discovery, or fallback to ordinary CA
validation for this path.

The sender relay pins the TLS peer to the SPKI in the recipient's signed route
before sending an opaque forwarding request. The destination checks that the
route names its address, persistent relay identity, and currently persisted
TLS SPKI before accepting it. A relay certificate can rotate only after a newer
root-signed route containing the new SPKI has been published; a legacy route
without this versioned field is rejected rather than guessed or upgraded.

Cross-relay forwarding carries an opaque MLS record, its explicit target
devices, and the recipient's signed routing record. The sending relay signs
the forwarding envelope. The destination accepts only when all of the
following hold:

- the recipient root signature and route revision verify;
- the route names the destination address, relay identity, and TLS SPKI; and
- the record recipient equals the route identity.

The destination applies its ordinary authorization, active/dormant, revocation,
per-device ACK, and retention rules. It never receives MLS keys or plaintext.
The sender keeps an outbound queue until destination acceptance. Acceptance
does not replicate long-term history; recipient delivery state and the
14-day window belong solely to the destination relay.

If the destination has a later valid route, it returns `MOVED` with that
user-signed record. The sender verifies it and retries the queued opaque event
against the new route. Relay signatures authenticate only relay transport;
they grant no user, device, routing, or MLS authority.
