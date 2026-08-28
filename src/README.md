# Source

This directory contains Pigeon's Rust source code.

- `shared/` — common protocol, identity, signed-routing, and library code.
- `server/` — the Pigeon coordination/delivery server.
- `client/` — the shared cross-platform client.

The repository is intended to use these components as members of a Cargo workspace.

The architecture separates stable cryptographic identity from mutable server routing. Clients own identity authority; servers provide reliable coordination and delivery.
