use anyhow::{bail, Context, Result};
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ServerSettings {
    pub(super) listen: String,
    pub(super) public_address: String,
    pub(super) database: String,
    pub(super) certificate: String,
    pub(super) private_key: String,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8443".into(),
            public_address: "127.0.0.1:8443".into(),
            database: "pigeon-server.sqlite3".into(),
            certificate: "pigeon-server-cert.der".into(),
            private_key: "pigeon-server-key.der".into(),
        }
    }
}

impl ServerSettings {
    pub(super) fn from_config(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path)
            .with_context(|| format!("read relay config {}", path.display()))?;
        let mut values = BTreeMap::new();
        for (line_number, raw_line) in source.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                bail!("{}:{}: expected key=value", path.display(), line_number + 1);
            };
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || value.is_empty() {
                bail!(
                    "{}:{}: empty config key or value",
                    path.display(),
                    line_number + 1
                );
            }
            if !matches!(
                key,
                "listen" | "public_address" | "database" | "certificate" | "private_key"
            ) {
                bail!(
                    "{}:{}: unknown relay config key {key}",
                    path.display(),
                    line_number + 1
                );
            }
            if values.insert(key, value.to_owned()).is_some() {
                bail!(
                    "{}:{}: duplicate relay config key {key}",
                    path.display(),
                    line_number + 1
                );
            }
        }
        let required = |key: &str| -> Result<String> {
            values.get(key).cloned().with_context(|| {
                format!(
                    "{}: missing required relay config key {key}",
                    path.display()
                )
            })
        };
        Ok(Self {
            listen: required("listen")?,
            public_address: required("public_address")?,
            database: required("database")?,
            certificate: required("certificate")?,
            private_key: required("private_key")?,
        })
    }

    pub(super) fn validate(&self) -> Result<()> {
        for (label, value) in [
            ("listen", &self.listen),
            ("public_address", &self.public_address),
            ("database", &self.database),
            ("certificate", &self.certificate),
            ("private_key", &self.private_key),
        ] {
            if value.trim().is_empty() || value.contains('\n') || value.contains('\r') {
                bail!("invalid empty or multiline relay {label}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ServerSettings;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn parses_complete_packaged_config() {
        let path = std::env::temp_dir().join(format!(
            "pigeon-server-config-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(
            &path,
            "# Pigeon relay\nlisten=0.0.0.0:8443\npublic_address=relay.example:8443\ndatabase=/var/lib/pigeon/relay.sqlite3\ncertificate=/var/lib/pigeon/tls/cert.der\nprivate_key=/var/lib/pigeon/tls/key.der\n",
        ).unwrap();
        let settings = ServerSettings::from_config(&path).unwrap();
        assert_eq!(settings.public_address, "relay.example:8443");
        settings.validate().unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_missing_or_unknown_config_fields() {
        let path = std::env::temp_dir().join(format!(
            "pigeon-server-config-invalid-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, "listen=127.0.0.1:8443\nunknown=value\n").unwrap();
        assert!(ServerSettings::from_config(&path).is_err());
        fs::remove_file(path).unwrap();
    }
}
