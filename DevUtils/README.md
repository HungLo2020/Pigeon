# Local development launchers

Run either script from any directory; both locate the repository from the script path.

```bash
python3 DevUtils/RunRelay.py
python3 DevUtils/RunClient.py
```

## Install the rolling release

To install Pigeon without a local Rust or Node build, clone the repository and
run the matching standard-library installer. Each script queries
`HungLo2020/Pigeon`'s rolling `latest` release, selects the local Debian
architecture, downloads the package and `SHA256SUMS`, verifies the package
checksum, then invokes `sudo apt install`.

```bash
git clone https://github.com/HungLo2020/Pigeon.git
cd Pigeon
python3 DevUtils/InstallLatestClient.py
python3 DevUtils/InstallLatestServer.py
```

The server installer never removes `/etc/pigeon` or `/var/lib/pigeon`. On a
fresh relay installation it prints the required next step:

```bash
sudo pigeon-setup
```

Use `--verify-only` with either installer to exercise release discovery,
download, and checksum verification without invoking `apt`.

`RunRelay.py` listens on `127.0.0.1:8443` and retains its SQLite database and generated development TLS certificate/key in `DevUtils/local-relay/`. Override the address or location with `--listen` and `--state-dir`.

`RunRelay.py` runs `cargo build -p pigeon-server` on every launch, then invokes that freshly built binary. `RunClient.py` incrementally builds the frontend, checks/builds Tauri, and builds the Rust client core before launching. It automatically uses the local relay certificate created by `RunRelay.py`; for another relay, pass its pinned certificate with `--certificate PATH`. It deliberately leaves account state in Tauri's normal per-user application-data directory, so client identity and conversations survive runs. The frontend must first have its dependencies installed with:

```bash
npm --prefix src/client/frontend install
```

Use Ctrl+C to stop either launcher; its child process exit status is returned by the script.
