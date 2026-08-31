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

For an already configured, active relay, the server installer reloads systemd
and restarts `pigeon-server` after the package upgrade, then verifies a new
active PID. A configured relay that was intentionally stopped remains stopped;
a fresh package installation is never started by the installer.

Use `--verify-only` with either installer to exercise release discovery,
download, and checksum verification without invoking `apt`.

`InstallLatestClient.py` manages only the invoking user's
`pigeon-client-daemon.service`: it records an active daemon PID before apt,
reloads the user manager, and restarts the daemon only when it was already
active (requiring a new PID). A deliberately stopped daemon stays stopped. On
a fresh installation it enables and starts the user unit for that user; it
never uses a global or system-level client service.

`RunRelay.py` listens on `127.0.0.1:8443` and retains its SQLite database and generated development TLS certificate/key in `DevUtils/local-relay/`. Override the address or location with `--listen` and `--state-dir`.

`RunRelay.py` runs `cargo build -p pigeon-server` on every launch, then invokes that freshly built binary. `RunClient.py` incrementally builds the frontend, checks/builds Tauri, and builds both the Rust client core and `pigeon-client-daemon` before launching. The daemon remains running after the GUI closes, so it can synchronize new messages. `--profile alice` gives both the GUI and daemon a separate persistent account-data directory and Unix socket; use separate profiles for multi-client testing. It automatically uses the local relay certificate created by `RunRelay.py`; for another relay, pass its pinned certificate with `--certificate PATH`. The frontend must first have its dependencies installed with:

```bash
npm --prefix src/client/frontend install
```

Use Ctrl+C to stop either launcher; its child process exit status is returned by the script.
