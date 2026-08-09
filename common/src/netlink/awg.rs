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

/// Appends the device-level attributes for whichever of `Obfuscation`'s fields are set - omitted
/// fields are left unmentioned (not sent as zero/default), matching AmneziaWG's own "unset means
/// kernel module default" semantics. Fallible only because `header_protection_key` needs base64
/// decoding like any other key.
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
pub fn push_obfuscation_attrs(
    attrs: &mut Vec<AmneziaWireguardAttribute>,
    o: &Obfuscation,
) -> Result<()> {
    if let Some(v) = o.jc {
        attrs.push(AmneziaWireguardAttribute::JC(v));
    }
    if let Some(v) = o.jmin {
        attrs.push(AmneziaWireguardAttribute::Jmin(v));
    }
    if let Some(v) = o.jmax {
        attrs.push(AmneziaWireguardAttribute::Jmax(v));
    }
    if let Some(v) = o.s1 {
        attrs.push(AmneziaWireguardAttribute::S1(v));
    }
    if let Some(v) = o.s2 {
        attrs.push(AmneziaWireguardAttribute::S2(v));
    }
    if let Some(v) = o.h1 {
        attrs.push(AmneziaWireguardAttribute::H1Range(u32_range_pack(v, v)));
    }
    if let Some(v) = o.h2 {
        attrs.push(AmneziaWireguardAttribute::H2Range(u32_range_pack(v, v)));
    }
    if let Some(v) = o.h3 {
        attrs.push(AmneziaWireguardAttribute::H3Range(u32_range_pack(v, v)));
    }
    if let Some(v) = o.h4 {
        attrs.push(AmneziaWireguardAttribute::H4Range(u32_range_pack(v, v)));
    }
    if let Some(v) = o.s3 {
        attrs.push(AmneziaWireguardAttribute::S3(v));
    }
    if let Some(v) = o.s4 {
        attrs.push(AmneziaWireguardAttribute::S4(v));
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
