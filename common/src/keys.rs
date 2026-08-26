//! X25519 key wire format only - no generation. Every private/public key an interface or peer
//! needs comes straight from the `ExtensionServiceConfig`-rendered config file; nothing here ever
//! generates or persists a key locally - keys are the config-renderer's responsibility, not this
//! daemon's.

use anyhow::{Context, Result};

/// Base64-decodes a 32-byte key - the wire format every AmneziaWG identity (private/public key)
/// uses, both over the netlink genl attributes and in the config file.
pub fn decode_key(b64: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("invalid base64 key")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key is not 32 bytes"))
}
