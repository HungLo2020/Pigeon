//! Relay TLS material is operational transport state, distinct from relay
//! identity and user-authorized routing records.

use anyhow::Result;
use rcgen::generate_simple_self_signed;
use std::{fs, path::Path};

pub(super) fn ensure_certificate(cert: &str, key: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    if Path::new(cert).exists() && Path::new(key).exists() {
        return Ok((fs::read(cert)?, fs::read(key)?));
    }
    let generated = generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate = generated.cert.der().to_vec();
    let private_key = generated.key_pair.serialize_der();
    fs::write(cert, &certificate)?;
    fs::write(key, &private_key)?;
    eprintln!("generated development TLS certificate at {cert}");
    Ok((certificate, private_key))
}
