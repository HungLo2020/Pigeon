# Server

The Pigeon server provides reliable communication coordination without owning user identity.

Expected responsibilities include:

- signed device/routing state for users currently using the server
- encrypted message delivery and offline queues
- acknowledgements and retention/expiry
- presence and call signaling
- encrypted blob/attachment transfer or bounded storage
- TURN/SFU integration points
- rate limiting and abuse/resource controls
- cross-server delivery when communicating with users on other Pigeon servers

The server is operationally authoritative for current delivery state, but cryptographically constrained by user and device signatures.

It must never require plaintext message/media contents, possess user private identity keys, or treat its hostname as part of a user's identity.

Users must be able to migrate to another Pigeon server while keeping the same cryptographic identity.
