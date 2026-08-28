# Pigeon Server

The Pigeon server provides reliable coordination and recent synchronization without owning user identity or permanent conversation history.

Expected responsibilities include:

- user/device registration using cryptographically verifiable identity and device records
- current signed routing revision for identities using the server
- encrypted message delivery and per-device acknowledgements
- recent encrypted synchronization state
- presence and connection coordination
- encrypted attachment transfer/storage within the retention window
- call signaling and integration points for TURN/SFU media infrastructure
- temporary migration/forwarding records when an identity moves to another server

## Retention

- Encrypted content is retained for at most **14 days**, or until it has been delivered to all currently authorized devices for the relevant identities, whichever happens first.
- Revoked devices do not block deletion.
- Long-term conversation archives must not be retained by the server as part of normal Pigeon operation.
- Small operational control state may persist while an identity uses the server.

## Authority Boundary

The server may be authoritative for recent delivery and synchronization state, but it must never:

- own or redefine a user's cryptographic identity
- add a valid device without appropriate cryptographic authorization
- forge a valid server migration/routing revision
- decrypt message contents
- become the permanent canonical history store

Server addresses are mutable routing metadata. A user moving to another server remains the same cryptographic identity.
