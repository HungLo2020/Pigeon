# Pigeon Server

The Pigeon server provides reliable coordination and recent synchronization without owning user identity or permanent conversation history.

Expected responsibilities include:

- user/device registration using cryptographically verifiable identity and device records
- current signed routing revision for identities using the server
- device last-seen tracking and active/dormant operational state
- encrypted message delivery and per-device acknowledgements
- recent encrypted synchronization state
- presence and connection coordination
- encrypted attachment transfer/storage within the retention window
- call signaling and integration points for TURN/SFU media infrastructure
- temporary migration/forwarding records when an identity moves to another server

## Device State

- **Active** devices are authorized and participate in required delivery acknowledgement.
- **Dormant** devices remain authorized but stop participating as delivery targets after more than 90 days of inactivity.
- A dormant device that reconnects with a still-valid credential becomes active again automatically.
- **Revoked** devices are removed only through a valid user-authorized identity revocation event.
- The server may mark devices dormant based on inactivity, but it must never revoke device authorization on its own.

## Retention

- Encrypted content is retained for at most **14 days**, or until it has been delivered to all active authorized devices for the relevant identities, whichever happens first.
- An active device that has been offline for less than 90 days continues to block early deletion until it acknowledges the content or the 14-day maximum is reached.
- Dormant and revoked devices do not block deletion.
- Long-term conversation archives must not be retained by the server as part of normal Pigeon operation.
- Small operational control state may persist while an identity uses the server, including device authorization, active/dormant state, last-seen timestamps, current routing state, and delivery bookkeeping.

## Authority Boundary

The server may be authoritative for recent delivery, synchronization, observed activity, and active/dormant operational state, but it must never:

- own or redefine a user's cryptographic identity
- add a valid device without appropriate cryptographic authorization
- revoke an authorized device without a valid user-authorized revocation event
- forge a valid server migration/routing revision
- decrypt message contents
- become the permanent canonical history store

Server addresses are mutable routing metadata. A user moving to another server remains the same cryptographic identity.

## Debian relay deployment

The `pigeon-server` Debian package installs the relay binary, `pigeon-setup`,
and a disabled `pigeon-server.service` unit. Package installation creates the
non-login `pigeon` service account but does not expose a partially configured
listener. Run `sudo pigeon-setup` to select the bind/public addresses and TLS
material. It writes `/etc/pigeon/pigeon-server.conf`, keeps the SQLite database,
relay identity, and TLS material under `/var/lib/pigeon`, initializes the relay
as the `pigeon` account, and then enables the service.

The daemon also supports `--config PATH` for an explicit key/value config and
`--initialize-only` for setup tooling. Existing development CLI flags remain
available. Relay logs use the normal systemd journal:

```bash
journalctl -u pigeon-server -f
```
