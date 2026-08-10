//! X25519 key generation for this offline tool only - the opposite trust boundary from
//! `common::keys` (wire-format decode only, deliberately no generation, since a live daemon must
//! never generate its own keys - see that module's doc comment). `patches` runs offline/CI-invoked,
//! analogous to a human once running `wg genkey` by hand.

use anyhow::Result;
use base64::Engine;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// Generates a fresh X25519 private key, base64-encoded - the same wire format
/// `common::keys::decode_key` expects to read back.
pub fn generate_private_key() -> String {
    let secret = StaticSecret::random_from_rng(OsRng);
    base64::engine::general_purpose::STANDARD.encode(secret.to_bytes())
}

/// Derives the base64-encoded X25519 public key for a base64-encoded private key - needed when
/// rendering a peer entry on the *other* end of a mesh link, which only ever gets that node's
/// public key, never its private key.
pub fn public_key_from_private(private_b64: &str) -> Result<String> {
    let bytes = common::keys::decode_key(private_b64)?;
    let public = PublicKey::from(&StaticSecret::from(bytes));
    Ok(base64::engine::general_purpose::STANDARD.encode(public.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_key_common_keys_can_decode() {
        let key = generate_private_key();
        common::keys::decode_key(&key).expect("generated key must be valid base64 32 bytes");
    }

    #[test]
    fn generates_different_keys_on_each_call() {
        let a = generate_private_key();
        let b = generate_private_key();
        assert_ne!(a, b);
    }

    #[test]
    fn derives_a_public_key_common_keys_can_decode() {
        let private = generate_private_key();
        let public = public_key_from_private(&private).expect("valid private key");
        common::keys::decode_key(&public)
            .expect("derived public key must be valid base64 32 bytes");
    }

    #[test]
    fn derives_the_same_public_key_for_the_same_private_key() {
        let private = generate_private_key();
        let a = public_key_from_private(&private).unwrap();
        let b = public_key_from_private(&private).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derives_different_public_keys_for_different_private_keys() {
        let a = public_key_from_private(&generate_private_key()).unwrap();
        let b = public_key_from_private(&generate_private_key()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_a_malformed_private_key() {
        assert!(public_key_from_private("not-valid-base64!!").is_err());
    }
}
