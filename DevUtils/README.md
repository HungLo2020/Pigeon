# Local development launchers

Run either script from any directory; both locate the repository from the script path.

```bash
python3 DevUtils/RunRelay.py
python3 DevUtils/RunClient.py
```

`RunRelay.py` listens on `127.0.0.1:8443` and retains its SQLite database and generated development TLS certificate/key in `DevUtils/local-relay/`. Override the address or location with `--listen` and `--state-dir`.

`RunClient.py` builds the existing Rust client core and launches the existing Tauri development app. It deliberately leaves account state in Tauri's normal per-user application-data directory, so client identity and conversations survive runs. The frontend must first have its dependencies installed with:

```bash
npm --prefix src/client/frontend install
```

Use Ctrl+C to stop either launcher; its child process exit status is returned by the script.
