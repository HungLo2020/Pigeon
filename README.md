# Pigeon

Pigeon is a sovereign, end-to-end encrypted communication platform designed so that users—not servers, phone numbers, email providers, or third-party accounts—own their identities and long-term communication history.

## Goals

- Direct text messaging and voice/video calls.
- Group text messaging and group voice/video calls.
- Discord-style communities with persistent text and voice channels.
- Live video and screen streaming.
- iOS and Linux as primary platforms, with room for others.
- Cryptographic identities instead of phone numbers, email addresses, or provider-owned usernames.
- End-to-end encryption for messages, files, calls, streams, and group communication.
- Infrastructure is untrusted and must not be able to impersonate users or decrypt communication.
- Reliable server-backed synchronization without making the server the permanent owner of conversation history.

## Core Model

Pigeon separates **identity**, **routing**, **recent synchronization**, and **long-term history**.

- A user's identity is the complete canonical immutable account genesis and is
  not tied to a server. Its SHA-256 compact ID is useful for display/indexing,
  but never proves identity equality or global uniqueness.
- Users control a portable, password-encrypted backup containing root and
  independent recovery authority. Import always creates a fresh device through
  a recovery-authorized roster transition; it does not recreate history or MLS
  epoch secrets that were not explicitly retained or backed up.
- A user's current server is mutable signed routing metadata.
- Contacts exchange self-authenticating signed contact cards containing a
  public identity and current routing record. QR codes, copyable links/text,
  and shareable contact files are interchangeable encodings of that card.
- Contacts cache the latest valid signed routing record they have seen for each identity.
- Servers coordinate delivery, device synchronization, presence, signaling, and recent encrypted content.
- Servers retain content for at most 14 days, or until it has been delivered to all active authorized devices for the relevant identities, whichever happens first.
- Devices inactive for more than 90 days become dormant and stop blocking server-side delivery completion, but remain cryptographically authorized until explicitly revoked by the user.
- Devices retain long-term history according to local user-configurable retention policies.
- Server changes are signed identity events and should automatically propagate to the user's other devices and contacts.
- There is no global authoritative Pigeon identity directory.

Canonical genesis, rather than a compact ID, is the equality and authorization
anchor at protocol and storage boundaries. Two byte-distinct valid genesis
records remain separate contacts/accounts even if a controlled test fixture or
an improbable hash collision gives them the same short ID. The UI may surface
that identifier collision, but it must never merge state.

## Device States

Each device associated with an identity has one of three states:

- **Active** — authorized and included as a delivery target. An active device blocks early server deletion until it acknowledges applicable content or the 14-day maximum is reached.
- **Dormant** — still cryptographically authorized, but no longer an active delivery target after more than 90 days without activity. Reconnecting automatically returns the device to active state after it proves its valid device authorization.
- **Revoked** — explicitly removed from the identity by the user. A revoked device no longer receives content, no longer blocks deletion, and must be explicitly re-added before it can participate again.

The server may determine inactivity and mark an authorized device dormant, but it must never revoke a device from an identity on its own.

## Device Retention

Individual devices should support configurable local history retention, with options such as:

- 30 days
- 90 days
- 1 year
- 5 years
- forever

Server retention is intentionally much shorter than device retention.

## Technology and Repository Layout

- Pigeon is implemented primarily in Rust.
- The repository is intended to be a Cargo workspace.
- `src/shared/` contains platform-neutral protocol and shared library code used by both client and server.
- `src/server/` contains the Pigeon server implementation.
- `src/client/` contains the shared client implementation.
- `src/client/core/` contains UI- and platform-independent client logic.
- `src/client/tauri/` contains the Tauri application shell and platform integration.
- `src/client/frontend/` contains the shared Tauri frontend.
- `resources/` contains non-source assets such as icons and bundled imagery.

The client core should remain independent of Tauri so communication, identity, cryptography, synchronization, retention, and protocol logic can be reused across platforms.

## Architecture Decisions

- [MLS for encrypted conversation state](docs/architecture/0001-mls-messaging.md)
- [Sovereign identity and peer-discovered routing](docs/architecture/0002-sovereign-identity-and-peer-discovery.md)
- [Devices, groups, relay, and first milestone](docs/architecture/0003-devices-groups-relay-and-first-milestone.md)
- [Secure add-device authorization and bootstrap](docs/architecture/0005-secure-add-device-bootstrap.md)
- [Immutable account genesis and recovery-gated authority](docs/architecture/0006-account-genesis-and-recovery-authority.md)

## Status

Pigeon is currently in the architecture and protocol-design phase.

See [PROJECT.md](PROJECT.md) for the project requirements and architecture.

## CI and rolling packages

GitHub Actions builds the actual Tauri application from
`src/client/tauri/tauri.conf.json`. `CI` runs on pushes and pull requests for
`main`, including the locked frontend build, Rust checks, and two independent
Debian packages. `pigeon-client` contains the Tauri desktop client and its
desktop runtime dependencies; `pigeon-server` contains only the relay binary
and is validated to exclude Tauri, WebKit, and frontend assets. Both packages
share one workspace version and source commit, but can be built independently
through `DevUtils/build_debian_packages.py --client` or `--server`.

Installing `pigeon-server` creates a non-login `pigeon` account and the
`pigeon-server` systemd unit, but does not enable it. Run `sudo pigeon-setup`
to choose the listener/public address and TLS material, initialize persistent
state below `/var/lib/pigeon`, write `/etc/pigeon/pigeon-server.conf`, and then
enable the relay. The package never stores mutable state below `/usr`; relay
logs are available through `journalctl -u pigeon-server`.

## Linux desktop client daemon

On Linux, `pigeon-client` also installs `pigeon-client-daemon` and the
`pigeon-client-daemon.service` systemd **user** unit. The daemon runs as the
logged-in user, never as root. It is the sole owner of local account files,
relay connections, MLS processing, sync, history writes, and background
delivery. The Tauri app is only a typed local IPC client and reconnects to the
daemon after a restart; closing its window does not stop recent-message sync.

The socket is `$XDG_RUNTIME_DIR/pigeon/pigeon-client.sock`, inside a `0700`
directory with a `0600` socket and same-UID peer validation. Client data lives
in `$XDG_DATA_HOME/pigeon` (or `~/.local/share/pigeon`). The package never
globally enables another local user's daemon. `InstallLatestClient.py` enables
the user unit for the installing desktop user on a fresh install; it can be
managed with:

```bash
systemctl --user status pigeon-client-daemon
systemctl --user restart pigeon-client-daemon
journalctl --user -u pigeon-client-daemon
```

When no GUI is connected, a newly synchronized message produces a
privacy-preserving desktop notification with no message preview. Development
profiles use an independent data directory and daemon socket through
`python3 DevUtils/RunClient.py --profile alice`.

## Relay discovery and first contact

Relay selection accepts an explicit `host:port` (including a direct IP), a
hostname, or an HTTPS descriptor URL. A hostname is resolved at
`https://host/.well-known/pigeon-relay`; an explicit URL such as
`https://example.com/relay` is fetched exactly as entered. The public,
versioned descriptor contains the canonical relay address plus its Ed25519
relay-identity and TLS-SPKI fingerprints.

Direct `host:port` onboarding supports self-signed development relays with an
explicit trust-on-first-use confirmation: Pigeon displays both fingerprints,
the user confirms them, and then the client pins them in its root-signed
routing record. There is no later certificate fallback or silent identity
change. The packaged `pigeon-setup` prints the connection value and both
fingerprints after configuration.

After successful main-branch CI, `Release latest` replaces the rolling
`latest` release/tag with both packages and one `SHA256SUMS` file. `Debian
package release` is manually dispatched and similarly replaces the independent
`debian` release/tag. The manually dispatched iOS workflow remains client-only:
it validates the intended macOS/Tauri build inputs without requiring signing or
publishing an IPA.
