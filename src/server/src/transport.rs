//! Length-delimited relay protocol framing.
use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) async fn read_frame<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let size = stream.read_u32().await? as usize;
    if size > 16 * 1024 * 1024 {
        bail!("frame too large");
    }
    let mut value = vec![0; size];
    stream.read_exact(&mut value).await?;
    Ok(value)
}
pub(super) async fn write_frame<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    bytes: &[u8],
) -> Result<()> {
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}
