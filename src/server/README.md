# Server / Relay

The Pigeon relay is intentionally untrusted, replaceable infrastructure.

Expected responsibilities include:

- temporary encrypted message queues
- acknowledgements and expiry
- encrypted blob transfer/storage
- routing and delivery support
- signaling or integration points for media infrastructure

The relay must never own user identity or require plaintext message contents.
