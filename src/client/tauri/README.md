# Tauri Application

This package is the Linux desktop/iOS host for the shared frontend in
`../frontend`. It exposes a small typed command surface (`account_status`,
`create_identity`, `fetch_messages`, `send_direct`, and `send_group`) and does
not expose relay, MLS, key, routing, or device protocol objects to JavaScript.

The current client core is still a CLI binary; commands invoke that binary
through typed Rust wrappers. Set `PIGEON_CLIENT_BIN` when it is not on `PATH`
and `PIGEON_CERTIFICATE` to the operator-provided relay certificate used by the
existing pinned client core. This is a transitional integration seam; protocol
logic remains in Rust core and is not duplicated in Tauri or TypeScript.

For Linux development: `npm --prefix ../frontend install`, then
`cargo tauri dev --config tauri.conf.json`. The config and capability layout are
Tauri v2/iOS-ready, but iOS builds require macOS, Xcode, and the Apple signing
toolchain, which are not available on Linux hosts.
