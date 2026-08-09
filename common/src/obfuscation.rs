//! AmneziaWG's device-level obfuscation parameters, covering the full protocol surface of the
//! current (v3.0.20260805) kernel module - confirmed field-by-field against
//! amneziawg-linux-kernel-module's `src/netlink.c` `device_policy` table and
//! amneziawg-tools' `src/config.c` (the authoritative list of what's actually user-configurable;
//! the kernel module's own README only documents the original nine).
//!
//! Grouped by when AmneziaWG introduced them - not a wire-format distinction, just for orientation:
//! - jc/jmin/jmax/s1/s2/h1-h4: the original set (junk packets before the handshake, magic header
//!   replacement for init/response packets).
//! - s3/s4: junk size for cookie-reply and transport (data) packets - s1/s2's original scope was
//!   only the handshake init/response packets.
//! - i1-i5: decoy/cover packets with a configurable header spec, sent alongside real traffic.
//! - header_protection_key + (peer-level) AdvancedSecurity: encrypts the WireGuard packet header's
//!   own type/reserved fields with a separate key - a distinct obfuscation layer from the junk-
//!   packet tricks above. Requires AdvancedSecurity enabled on the peer(s) that should use it (see
//!   `PeerEntry` in `awg/src/config.rs`) - setting only `header_protection_key` here does nothing
//!   on its own.
//! - content_padding_addition, rekey_after_time, rekey_timeout, reject_after_time,
//!   keepalive_timeout, max_handshake_attempts: protocol timing/padding constants vanilla
//!   WireGuard hardcodes - configurable here specifically so they stop being a fixed, fingerprint-
//!   able signature.

use serde::Deserialize;

#[derive(Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Obfuscation {
    #[serde(default)]
    pub jc: Option<u16>,
    #[serde(default)]
    pub jmin: Option<u16>,
    #[serde(default)]
    pub jmax: Option<u16>,
    #[serde(default)]
    pub s1: Option<u16>,
    #[serde(default)]
    pub s2: Option<u16>,
    #[serde(default)]
    pub h1: Option<u32>,
    #[serde(default)]
    pub h2: Option<u32>,
    #[serde(default)]
    pub h3: Option<u32>,
    #[serde(default)]
    pub h4: Option<u32>,

    #[serde(default)]
    pub s3: Option<u16>,
    #[serde(default)]
    pub s4: Option<u16>,

    #[serde(default)]
    pub i1: Option<String>,
    #[serde(default)]
    pub i2: Option<String>,
    #[serde(default)]
    pub i3: Option<String>,
    #[serde(default)]
    pub i4: Option<String>,
    #[serde(default)]
    pub i5: Option<String>,

    /// Base64, same wire format/length as `InterfaceEntry::private_key` - decoded via
    /// `common::keys::decode_key`.
    #[serde(default)]
    pub header_protection_key: Option<String>,

    #[serde(default)]
    pub content_padding_addition: Option<u32>,
    #[serde(default)]
    pub rekey_after_time: Option<u32>,
    #[serde(default)]
    pub rekey_timeout: Option<u32>,
    #[serde(default)]
    pub reject_after_time: Option<u32>,
    #[serde(default)]
    pub keepalive_timeout: Option<u32>,
    #[serde(default)]
    pub max_handshake_attempts: Option<u32>,
}
