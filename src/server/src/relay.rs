use super::*;

pub(crate) fn relay_tls_spki(connection: &Connection) -> Result<[u8; 32]> {
    let value: Vec<u8> = connection
        .query_row("SELECT spki FROM relay_tls WHERE id = 1", [], |r| r.get(0))
        .context("relay TLS SPKI is not initialized")?;
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid persisted relay TLS SPKI"))
}
pub(crate) fn bind_relay_tls_spki(connection: &Connection, spki: [u8; 32]) -> Result<()> {
    let existing: Option<Vec<u8>> = connection
        .query_row("SELECT spki FROM relay_tls WHERE id = 1", [], |r| r.get(0))
        .optional()?;
    match existing {
        None => {
            connection.execute(
                "INSERT INTO relay_tls (id, spki) VALUES (1, ?1)",
                params![spki.to_vec()],
            )?;
        }
        Some(existing) if existing.as_slice() == spki => {}
        Some(_) => {
            // A certificate may change only after a root-signed v2 route that
            // names this relay and the new pin is already persisted.
            let routes = connection
                .prepare("SELECT route FROM routes_v2")?
                .query_map([], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let identity = relay_identity(connection)?;
            let approved = routes
                .iter()
                .filter_map(|bytes| decode::<RoutingRecord>(bytes).ok())
                .any(|route| {
                    route.relay_identity == identity && route.tls_spki_fingerprint == spki
                });
            if !approved {
                bail!("relay TLS SPKI changed without a newer signed routing record")
            }
            connection.execute(
                "UPDATE relay_tls SET spki = ?1 WHERE id = 1",
                params![spki.to_vec()],
            )?;
        }
    }
    Ok(())
}
pub(crate) fn set_relay_address(connection: &Connection, address: &str) -> Result<()> {
    connection.execute("INSERT INTO relay_config (name, value) VALUES ('address', ?1) ON CONFLICT(name) DO UPDATE SET value = excluded.value", params![address.as_bytes()])?;
    Ok(())
}
pub(crate) fn relay_address(connection: &Connection) -> Result<String> {
    let bytes: Vec<u8> = connection
        .query_row(
            "SELECT value FROM relay_config WHERE name = 'address'",
            [],
            |r| r.get(0),
        )
        .context("relay network address is not initialized")?;
    String::from_utf8(bytes).map_err(Into::into)
}
pub(crate) fn relay_identity(connection: &Connection) -> Result<[u8; 32]> {
    let secret: Option<Vec<u8>> = connection
        .query_row("SELECT secret FROM relay_identity WHERE id = 1", [], |r| {
            r.get(0)
        })
        .optional()?;
    let key = match secret {
        Some(secret) => SigningKey::from_bytes(
            &secret
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid persisted relay identity"))?,
        ),
        None => {
            let key = SigningKey::generate(&mut OsRng);
            connection.execute(
                "INSERT INTO relay_identity (id, secret) VALUES (1, ?1)",
                params![key.to_bytes().to_vec()],
            )?;
            key
        }
    };
    Ok(key.verifying_key().to_bytes())
}
pub(crate) fn relay_signer(connection: &Connection) -> Result<SigningKey> {
    let _ = relay_identity(connection)?;
    let secret: Vec<u8> =
        connection.query_row("SELECT secret FROM relay_identity WHERE id = 1", [], |r| {
            r.get(0)
        })?;
    Ok(SigningKey::from_bytes(&secret.try_into().map_err(
        |_| anyhow::anyhow!("invalid persisted relay identity"),
    )?))
}
