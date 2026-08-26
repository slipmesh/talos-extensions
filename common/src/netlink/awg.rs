//! Thin wrapper around `netlink-packet-amnezia-wireguard` + `genetlink` - talks the kernel
//! module's own genl family ("amneziawg", not "wireguard") directly rather than shelling out to
//! the `awg` CLI. This module only owns the raw `GetDevice`/`SetDevice` netlink transport;
//! interface/address/route management is `rt.rs` (a different netlink family).
//!
//! Ported from slipmesh-operators' `common::netlink::awg` (github.com/slipmesh/operators) -
//! functionally identical, just re-homed into a project with no Kubernetes dependency.

use crate::keys::decode_key;
use crate::obfuscation::Obfuscation;
use anyhow::{Context, Result};
use futures::StreamExt;
use genetlink::GenetlinkHandle;
use netlink_packet_amnezia_wireguard::range::u32_range_pack;
use netlink_packet_amnezia_wireguard::{
    AmneziaWireguardAttribute, AmneziaWireguardCmd, AmneziaWireguardMessage,
};
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;

/// Real WireGuard message-type constants (`enum message_type` in AmneziaWG's own
/// `messages.h`: `MESSAGE_HANDSHAKE_INITIATION=1, MESSAGE_HANDSHAKE_RESPONSE=2,
/// MESSAGE_HANDSHAKE_COOKIE=3, MESSAGE_DATA=4`) - what a fresh device's `h1..h4` already default
/// to (`device.c`'s `wg_init`: `memset`s the whole device to zero, then explicitly sets exactly
/// these four). Used below as the explicit "no header obfuscation" value for an unset `h1..h4` -
/// not `0`, which is a distinct (still-obfuscated, just wrong) magic value, not "disabled".
const REAL_H1: u32 = 1;
const REAL_H2: u32 = 2;
const REAL_H3: u32 = 3;
const REAL_H4: u32 = 4;

/// Appends every device-level obfuscation attribute AmneziaWG's `SetDevice` accepts.
///
/// `jc`/`jmin`/`jmax`/`s1`..`s4`/`h1`..`h4` are always sent, substituting each field's own real
/// kernel-module default (per `device.c`'s `wg_init`, which `memset`s the
/// whole device to zero and then only overrides `h1..h4` - see `REAL_H1`..`REAL_H4` above) for an
/// unset field, rather than omitting the attribute entirely. This is deliberate, not just
/// thorough: AmneziaWG's `SetDevice` treats an *omitted* attribute as "leave whatever's already
/// there alone" (`netlink.c`: `info->attrs[WGDEVICE_A_H1] ? nla_get_u64(...) : wg->init_header`),
/// not "reset to default" - so on a link this daemon previously configured *with* obfuscation,
/// omitting these attributes on a later run that now wants none would silently leave the kernel
/// serving the old junk-packet/magic-header config forever, even though the rendered config now
/// says otherwise: a peer speaking stock WireGuard cannot complete a handshake against a link
/// whose obfuscation was cleared in config this way, because the kernel-side state never
/// actually cleared. Always sending an explicit value - the real
/// kernel-module default when unset - is correct on *both* a brand-new device (identical to what
/// it would already be) and a previously-obfuscated one (actually clears it), so there's no need
/// to distinguish the two cases here.
///
/// `i1`..`i5`/`header_protection_key`/`content_padding_addition`/`rekey_after_time`/
/// `rekey_timeout`/`reject_after_time`/`keepalive_timeout`/`max_handshake_attempts` stay
/// omit-if-unset: none of them are populated by any interface in this workspace today (mesh links
/// only ever set jc/jmin/jmax/s1/s2/h1..h4; roadwarrior pools can set `header_protection_key`, but
/// never *unset* it once set - see `awg::config`'s `advanced_security` validation), so there's no
/// observed instance of the same stale-state bug for these, and (unlike h1..h4) their true
/// kernel-module "default" isn't a simple constant confirmable the same way (`rekey_after_time`
/// etc. read like runtime fallback thresholds, not raw values) - not worth guessing at without a
/// real bug to fix.
///
/// H1..H4 use the `*Range` variants (packed `u64`, `lo == hi == v` for our plain single-value
/// case via `u32_range_pack`) - the wire format AmneziaWG 3.0's kernel module actually expects,
/// not the NUL-terminated-string `H1`..`H4` variants, an older kernel module generation's format
/// (see this crate's git-rev pin comment in the workspace `Cargo.toml`). `s3`/`s4` and `i1`..`i5`
/// have no such split: the crate's plain `u16`/`String` variants already match the kernel's
/// `NLA_U16`/`NLA_NUL_STRING` policy for those. `content_padding_addition`/`rekey_after_time`/
/// `rekey_timeout`/`reject_after_time`/`keepalive_timeout`/`max_handshake_attempts` are plain
/// `u32` on the wire (confirmed against netlink.c's `device_policy`), with no packed/range
/// variant for these in the crate, unlike H1..H4.
///
/// Fallible only because `header_protection_key` needs base64 decoding like any other key.
pub fn push_obfuscation_attrs(
    attrs: &mut Vec<AmneziaWireguardAttribute>,
    o: &Obfuscation,
) -> Result<()> {
    attrs.push(AmneziaWireguardAttribute::JC(o.jc.unwrap_or(0)));
    attrs.push(AmneziaWireguardAttribute::Jmin(o.jmin.unwrap_or(0)));
    attrs.push(AmneziaWireguardAttribute::Jmax(o.jmax.unwrap_or(0)));
    attrs.push(AmneziaWireguardAttribute::S1(o.s1.unwrap_or(0)));
    attrs.push(AmneziaWireguardAttribute::S2(o.s2.unwrap_or(0)));
    attrs.push(AmneziaWireguardAttribute::S3(o.s3.unwrap_or(0)));
    attrs.push(AmneziaWireguardAttribute::S4(o.s4.unwrap_or(0)));
    {
        let v = o.h1.unwrap_or(REAL_H1);
        attrs.push(AmneziaWireguardAttribute::H1Range(u32_range_pack(v, v)));
    }
    {
        let v = o.h2.unwrap_or(REAL_H2);
        attrs.push(AmneziaWireguardAttribute::H2Range(u32_range_pack(v, v)));
    }
    {
        let v = o.h3.unwrap_or(REAL_H3);
        attrs.push(AmneziaWireguardAttribute::H3Range(u32_range_pack(v, v)));
    }
    {
        let v = o.h4.unwrap_or(REAL_H4);
        attrs.push(AmneziaWireguardAttribute::H4Range(u32_range_pack(v, v)));
    }
    if let Some(v) = &o.i1 {
        attrs.push(AmneziaWireguardAttribute::I1(v.clone()));
    }
    if let Some(v) = &o.i2 {
        attrs.push(AmneziaWireguardAttribute::I2(v.clone()));
    }
    if let Some(v) = &o.i3 {
        attrs.push(AmneziaWireguardAttribute::I3(v.clone()));
    }
    if let Some(v) = &o.i4 {
        attrs.push(AmneziaWireguardAttribute::I4(v.clone()));
    }
    if let Some(v) = &o.i5 {
        attrs.push(AmneziaWireguardAttribute::I5(v.clone()));
    }
    if let Some(key) = &o.header_protection_key {
        attrs.push(AmneziaWireguardAttribute::HeaderProtectionKey(
            decode_key(key).context("invalid header_protection_key")?,
        ));
    }
    if let Some(v) = o.content_padding_addition {
        attrs.push(AmneziaWireguardAttribute::ContentPaddingAddition(v));
    }
    if let Some(v) = o.rekey_after_time {
        attrs.push(AmneziaWireguardAttribute::RekeyAfterTime(v));
    }
    if let Some(v) = o.rekey_timeout {
        attrs.push(AmneziaWireguardAttribute::RekeyTimeout(v));
    }
    if let Some(v) = o.reject_after_time {
        attrs.push(AmneziaWireguardAttribute::RejectAfterTime(v));
    }
    if let Some(v) = o.keepalive_timeout {
        attrs.push(AmneziaWireguardAttribute::KeepaliveTimeout(v));
    }
    if let Some(v) = o.max_handshake_attempts {
        attrs.push(AmneziaWireguardAttribute::MaxHandshakeAttempts(v));
    }
    Ok(())
}

#[derive(Clone)]
pub struct AwgClient {
    handle: GenetlinkHandle,
}

impl AwgClient {
    pub fn connect() -> Result<Self> {
        let (connection, handle, _) =
            genetlink::new_connection().context("failed to open genetlink socket")?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    pub async fn get_device(&mut self, ifname: &str) -> Result<Vec<AmneziaWireguardAttribute>> {
        let msg = AmneziaWireguardMessage {
            cmd: AmneziaWireguardCmd::GetDevice,
            attributes: vec![AmneziaWireguardAttribute::IfName(ifname.to_string())],
        };
        let genlmsg: GenlMessage<AmneziaWireguardMessage> = GenlMessage::from_payload(msg);
        let mut nlmsg = NetlinkMessage::from(genlmsg);
        nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        let mut res = self
            .handle
            .request(nlmsg)
            .await
            .context("genetlink GetDevice request failed")?;

        let mut attrs = Vec::new();
        while let Some(result) = res.next().await {
            let rx_packet = result.context("genetlink response error")?;
            match rx_packet.payload {
                NetlinkPayload::InnerMessage(genlmsg) => attrs.extend(genlmsg.payload.attributes),
                NetlinkPayload::Error(e) => {
                    anyhow::bail!("GetDevice({ifname}) netlink error: {:?}", e.to_io())
                }
                _ => {}
            }
        }
        Ok(attrs)
    }

    pub async fn set_device(&mut self, attributes: Vec<AmneziaWireguardAttribute>) -> Result<()> {
        let msg = AmneziaWireguardMessage {
            cmd: AmneziaWireguardCmd::SetDevice,
            attributes,
        };
        let genlmsg: GenlMessage<AmneziaWireguardMessage> = GenlMessage::from_payload(msg);
        let mut nlmsg = NetlinkMessage::from(genlmsg);
        nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut res = self
            .handle
            .request(nlmsg)
            .await
            .context("genetlink SetDevice request failed")?;
        // This amneziawg kernel module doesn't always send a response despite NLM_F_ACK - an
        // empty stream is logged, not treated as failure.
        match res.next().await {
            Some(result) => {
                let rx_packet = result.context("genetlink response error")?;
                if let NetlinkPayload::Error(e) = rx_packet.payload {
                    // `code: None` means ACK per RFC 3549 2.3.2.2 - only `Some` is a real NACK.
                    if e.code.is_some() {
                        anyhow::bail!("SetDevice netlink error: {:?}", e.to_io());
                    }
                }
            }
            None => tracing::debug!(
                "SetDevice got no response at all (expected an ack/nack, but proceeding)"
            ),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push(o: &Obfuscation) -> Vec<AmneziaWireguardAttribute> {
        let mut attrs = Vec::new();
        push_obfuscation_attrs(&mut attrs, o).unwrap();
        attrs
    }

    /// The bug this whole function's doc comment describes: an all-`None` `Obfuscation` (a
    /// `plain: true` mesh link, see `mesh_config::MeshLink`) must still emit real, explicit
    /// attributes - never nothing - since AmneziaWG's `SetDevice` treats an omitted attribute as
    /// "leave the kernel's current value alone", not "reset to default".
    #[test]
    fn default_obfuscation_still_pushes_every_junk_and_header_attribute() {
        let attrs = push(&Obfuscation::default());
        assert!(attrs.contains(&AmneziaWireguardAttribute::JC(0)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::Jmin(0)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::Jmax(0)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::S1(0)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::S2(0)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::S3(0)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::S4(0)));
    }

    /// `h1..h4` default to WireGuard's own real per-packet-type magic values (`1..4`), not `0` -
    /// `0` would just be a different, still-wrong magic value, not "no header obfuscation". See
    /// `REAL_H1`..`REAL_H4`'s doc comment for where `1..4` comes from.
    #[test]
    fn default_obfuscation_headers_are_the_real_wireguard_message_types_not_zero() {
        let attrs = push(&Obfuscation::default());
        assert!(attrs.contains(&AmneziaWireguardAttribute::H1Range(u32_range_pack(1, 1))));
        assert!(attrs.contains(&AmneziaWireguardAttribute::H2Range(u32_range_pack(2, 2))));
        assert!(attrs.contains(&AmneziaWireguardAttribute::H3Range(u32_range_pack(3, 3))));
        assert!(attrs.contains(&AmneziaWireguardAttribute::H4Range(u32_range_pack(4, 4))));
    }

    #[test]
    fn explicit_obfuscation_values_are_used_verbatim() {
        let o = Obfuscation {
            jc: Some(4),
            jmin: Some(40),
            jmax: Some(70),
            h1: Some(12345),
            ..Obfuscation::default()
        };
        let attrs = push(&o);
        assert!(attrs.contains(&AmneziaWireguardAttribute::JC(4)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::Jmin(40)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::Jmax(70)));
        assert!(
            attrs.contains(&AmneziaWireguardAttribute::H1Range(u32_range_pack(
                12345, 12345
            )))
        );
        // Untouched h2 still falls back to its own real default, independent of h1 being set.
        assert!(attrs.contains(&AmneziaWireguardAttribute::H2Range(u32_range_pack(2, 2))));
    }

    /// `i1`..`i5`/`header_protection_key`/timing fields stay omit-if-unset (see this module's own
    /// doc comment for why) - unlike jc/jmin/jmax/s1..s4/h1..h4, an unset one of these must not
    /// appear in the pushed attributes at all.
    #[test]
    fn unset_decoy_and_timing_fields_are_omitted_not_defaulted() {
        let attrs = push(&Obfuscation::default());
        assert!(
            !attrs
                .iter()
                .any(|a| matches!(a, AmneziaWireguardAttribute::I1(_)))
        );
        assert!(
            !attrs
                .iter()
                .any(|a| matches!(a, AmneziaWireguardAttribute::HeaderProtectionKey(_)))
        );
        assert!(
            !attrs
                .iter()
                .any(|a| matches!(a, AmneziaWireguardAttribute::RekeyAfterTime(_)))
        );
    }
}
