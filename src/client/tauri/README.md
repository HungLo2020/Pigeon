# Tauri Application

This package is the Linux desktop/iOS host for the shared frontend in
`../frontend`. It exposes a small typed command surface (`account_status`,
`create_identity`, `fetch_messages`, `send_direct`, and `send_group`) and does
not expose relay, MLS, key, routing, or device protocol objects to JavaScript.

On Linux the current client core is invoked only by `pigeon-client-daemon`.
Tauri uses the daemon's permission-restricted typed Unix-socket IPC for every
state snapshot and command, then forwards daemon state events as
`pigeon://state`. Set `PIGEON_CLIENT_DAEMON_BIN` and `PIGEON_CLIENT_BIN` when
developing from an uninstalled tree. Protocol logic remains in Rust core and
is not duplicated in Tauri or TypeScript.

For Linux development: `npm --prefix ../frontend install`, then
`cargo tauri dev --config tauri.conf.json`. The config and capability layout are
Tauri v2/iOS-ready, but iOS builds require macOS, Xcode, and the Apple signing
toolchain, which are not available on Linux hosts.
