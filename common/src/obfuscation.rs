//! AmneziaWG's device-level obfuscation parameters, covering the full protocol surface of the
//! current (v3.0.20260805) kernel module - confirmed field-by-field against
//! amneziawg-linux-kernel-module's `src/netlink.c` `device_policy` table and
//! amneziawg-tools' `src/config.c` (the authoritative list of what's actually user-configurable;
//! the kernel module's own README only documents jc/jmin/jmax/s1/s2/h1-h4).
//!
//! Grouped below by what each knob actually does, matching the struct's own field order:
//! - jc/jmin/jmax: how many junk packets to send before the handshake, and their size range.
//! - s1-s4: junk size for each handshake-adjacent packet type - s1/s2 for init/response, s3/s4
//!   (AmneziaWG 3.0) extending the same idea to cookie-reply and transport (data) packets.
//! - h1-h4: magic header replacement values, one per packet type (init/response/cookie/transport).
//! - i1-i5: decoy/cover packets with a configurable header spec, sent alongside real traffic.
//! - header_protection_key: encrypts the WireGuard packet header's own type/reserved fields with a
//!   separate key - a distinct obfuscation layer from the junk-packet tricks above. Requires
//!   `AdvancedSecurity` enabled on the peer(s) that should use it (see `PeerEntry` in
//!   `awg/src/config.rs`) - setting only this field does nothing on its own.
//! - content_padding_addition, rekey_after_time, rekey_timeout, reject_after_time,
//!   keepalive_timeout, max_handshake_attempts: protocol timing/padding constants vanilla
//!   WireGuard hardcodes - configurable here specifically so they stop being a fixed,
//!   fingerprintable signature.

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
pub struct Obfuscation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jc: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jmin: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jmax: Option<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s1: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s2: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s4: Option<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h1: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h3: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h4: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i5: Option<String>,

    /// Base64, same wire format/length as `InterfaceEntry::private_key` - decoded via
    /// `common::keys::decode_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_protection_key: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_padding_addition: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekey_after_time: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekey_timeout: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_after_time: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_timeout: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_handshake_attempts: Option<u32>,

    /// AmneziaWG 3.1. Appends a random-length trailer to outgoing packets, sized against what
    /// the peer has been seen to send, so the wire lengths stop being a fingerprint. Receive-side
    /// length checks become "at least" rather than "exactly", so both ends may set it
    /// independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub random_trailers: Option<bool>,
    /// AmneziaWG 3.1. Suppresses cookie replies, which are a message type of their own and
    /// therefore a signature. The cost is the load-shedding those replies exist for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_cookies: Option<bool>,
}

/// The AmneziaWG module refuses a header protection key unless every junk size s1..s4 can hold
/// its nonce, and says why only in a debug log line that is off by default: userspace gets a bare
/// `EINVAL` from `SetDevice`. `netlink::awg` sends an unset size as 0.
pub const HEADER_PROTECTION_NONCE_SIZE: u16 = 12;

impl Obfuscation {
    /// Rejects combinations the kernel module refuses at `SetDevice`.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.header_protection_key.is_some() {
            let too_small: Vec<_> = [
                ("s1", self.s1),
                ("s2", self.s2),
                ("s3", self.s3),
                ("s4", self.s4),
            ]
            .into_iter()
            .filter(|(_, size)| size.unwrap_or(0) < HEADER_PROTECTION_NONCE_SIZE)
            .map(|(name, _)| name)
            .collect();
            anyhow::ensure!(
                too_small.is_empty(),
                "obfuscation.header_protection_key needs {} of at least {HEADER_PROTECTION_NONCE_SIZE}",
                too_small.join(", ")
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializing_omits_unset_fields_instead_of_writing_null() {
        let cfg = Obfuscation {
            jc: Some(4),
            ..Obfuscation::default()
        };
        let yaml = yaml_serde::to_string(&cfg).unwrap();
        assert!(yaml.contains("jc: 4"), "yaml was:\n{yaml}");
        assert!(!yaml.contains("null"), "yaml was:\n{yaml}");
    }

    fn header_protected(junk_sizes: [Option<u16>; 4]) -> Obfuscation {
        let [s1, s2, s3, s4] = junk_sizes;
        Obfuscation {
            header_protection_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
            s1,
            s2,
            s3,
            s4,
            ..Obfuscation::default()
        }
    }

    #[test]
    fn rejects_header_protection_key_with_a_junk_size_below_the_nonce() {
        let err = header_protected([Some(12), Some(12), Some(12), Some(11)])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("s4"), "{err}");
        assert!(!err.contains("s1"), "{err}");
    }

    #[test]
    fn rejects_header_protection_key_with_junk_sizes_left_unset() {
        let err = header_protected([None; 4])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("s1, s2, s3, s4"), "{err}");
    }

    #[test]
    fn accepts_header_protection_key_with_every_junk_size_holding_the_nonce() {
        assert!(header_protected([Some(12); 4]).validate().is_ok());
    }

    #[test]
    fn accepts_small_junk_sizes_without_header_protection() {
        let o = Obfuscation {
            s1: Some(0),
            ..Obfuscation::default()
        };
        assert!(o.validate().is_ok());
    }

    #[test]
    fn a_fully_unset_obfuscation_serializes_to_an_empty_mapping() {
        let yaml = yaml_serde::to_string(&Obfuscation::default()).unwrap();
        assert_eq!(yaml.trim(), "{}");
    }
}
