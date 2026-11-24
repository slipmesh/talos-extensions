//! Thin wrapper around `netlink-packet-amneziawg` + `genetlink` - talks the kernel
//! module's own genl family ("amneziawg", not "wireguard") directly rather than shelling out to
//! the `awg` CLI. This module only owns the raw `GetDevice`/`SetDevice` netlink transport;
//! interface/address/route management is `rt.rs` (a different netlink family).

use anyhow::{Context, Result};
use futures::StreamExt;
use genetlink::GenetlinkHandle;
use netlink_packet_amneziawg::AmneziaWireguardRange;
use netlink_packet_amneziawg::{
    AmneziaWireguardAttribute, AmneziaWireguardCmd, AmneziaWireguardMessage,
};
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use sliplib_config::Obfuscation;
use sliplib_secrets::wireguard::decode_key;

/// Appends every device-level obfuscation attribute AmneziaWG's `SetDevice` accepts.
///
/// `jc`/`jmin`/`jmax`/`s1`..`s4`/`h1`..`h4` are always sent, substituting each field's own real
/// kernel-module default (per `device.c`'s `wg_init`, which `memset`s the whole device to zero
/// and then only overrides `h1..h4` - see `obfuscation::DEFAULT_MAGIC_HEADERS`) for an unset
/// field, rather than omitting the attribute entirely. This is deliberate, not just
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
/// `i1`..`i5` and `header_protection_key` stay omit-if-unset. The module has no way to take a key
/// off an interface, and whether an empty decoy spec clears a decoy is not known, so an unset one
/// is not sent.
///
/// `content_padding_addition`/`rekey_after_time`/`rekey_timeout`/`reject_after_time`/
/// `keepalive_timeout`/`max_handshake_attempts` are ranges of two `u16` ends, out of which the
/// module draws. They are always sent, zero for an unset one: zero is the module's "not set",
/// and an omitted attribute would keep what an earlier config put there.
///
/// Fallible only because `header_protection_key` needs base64 decoding like any other key.
pub fn push_obfuscation_attrs(
    attrs: &mut Vec<AmneziaWireguardAttribute>,
    o: &Obfuscation,
) -> Result<()> {
    attrs.push(AmneziaWireguardAttribute::Jc(o.jc.unwrap_or(0)));
    attrs.push(AmneziaWireguardAttribute::Jmin(o.jmin.unwrap_or(0)));
    attrs.push(AmneziaWireguardAttribute::Jmax(o.jmax.unwrap_or(0)));
    attrs.push(AmneziaWireguardAttribute::S1(o.s1.unwrap_or(0)));
    attrs.push(AmneziaWireguardAttribute::S2(o.s2.unwrap_or(0)));
    attrs.push(AmneziaWireguardAttribute::S3(o.s3.unwrap_or(0)));
    attrs.push(AmneziaWireguardAttribute::S4(o.s4.unwrap_or(0)));
    let [h1, h2, h3, h4] = o.magic_headers();
    attrs.push(AmneziaWireguardAttribute::H1(wire(h1)));
    attrs.push(AmneziaWireguardAttribute::H2(wire(h2)));
    attrs.push(AmneziaWireguardAttribute::H3(wire(h3)));
    attrs.push(AmneziaWireguardAttribute::H4(wire(h4)));
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
            decode_key(key.expose())
                .map_err(|e| anyhow::anyhow!("invalid header_protection_key: {e}"))?,
        ));
    }
    let sent = |value: Option<sliplib_config::Range<u16>>| value.map(wire).unwrap_or_default();
    attrs.push(AmneziaWireguardAttribute::ContentPaddingAddition(sent(
        o.content_padding_addition,
    )));
    attrs.push(AmneziaWireguardAttribute::RekeyAfterTime(sent(
        o.rekey_after_time,
    )));
    attrs.push(AmneziaWireguardAttribute::RekeyTimeout(sent(
        o.rekey_timeout,
    )));
    attrs.push(AmneziaWireguardAttribute::RejectAfterTime(sent(
        o.reject_after_time,
    )));
    attrs.push(AmneziaWireguardAttribute::KeepaliveTimeout(sent(
        o.keepalive_timeout,
    )));
    attrs.push(AmneziaWireguardAttribute::MaxHandshakeAttempts(sent(
        o.max_handshake_attempts,
    )));
    // Always sent: these are obfuscation switches, and an omitted attribute leaves whatever the
    // kernel already has.
    attrs.push(AmneziaWireguardAttribute::RandomTrailers(
        o.random_trailers.unwrap_or(false),
    ));
    attrs.push(AmneziaWireguardAttribute::DisableCookies(
        o.disable_cookies.unwrap_or(false),
    ));
    Ok(())
}

/// `range` as the module takes it.
pub fn wire<T: sliplib_config::End>(range: sliplib_config::Range<T>) -> AmneziaWireguardRange<T> {
    AmneziaWireguardRange {
        lo: range.lo(),
        hi: range.hi(),
    }
}

/// The 3.1 attributes removed, or `None` if there were none to remove.
///
/// Generic netlink validates against the family's own `maxattr`, so a module that predates
/// AmneziaWG 3.1 does not ignore `WGDEVICE_A_RANDOM_TRAILERS` and `WGDEVICE_A_DISABLE_COOKIES` -
/// it fails the entire `SetDevice`, leaving the interface unconfigured. The two are optional
/// obfuscation switches, so dropping them and retrying keeps a node reachable on an older module
/// instead of failing to bring its mesh up at all.
fn without_31_attributes(
    attrs: &[AmneziaWireguardAttribute],
) -> Option<Vec<AmneziaWireguardAttribute>> {
    let is_31 = |a: &AmneziaWireguardAttribute| {
        matches!(
            a,
            AmneziaWireguardAttribute::RandomTrailers(_)
                | AmneziaWireguardAttribute::DisableCookies(_)
        )
    };
    attrs
        .iter()
        .any(is_31)
        .then(|| attrs.iter().filter(|a| !is_31(a)).cloned().collect())
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
        match self.set_device_once(attributes.clone()).await {
            Ok(()) => Ok(()),
            Err(e) => match without_31_attributes(&attributes) {
                Some(older) => {
                    tracing::warn!(
                        error = %e,
                        "SetDevice refused; retrying without AmneziaWG 3.1's device switches, \
                         which a module older than 3.1 rejects outright"
                    );
                    self.set_device_once(older).await
                }
                None => Err(e),
            },
        }
    }

    async fn set_device_once(&mut self, attributes: Vec<AmneziaWireguardAttribute>) -> Result<()> {
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
    use sliplib_secrets::wireguard::encode_key;

    fn push(o: &Obfuscation) -> Vec<AmneziaWireguardAttribute> {
        let mut attrs = Vec::new();
        push_obfuscation_attrs(&mut attrs, o).unwrap();
        attrs
    }

    /// The bug this whole function's doc comment describes: an all-`None` `Obfuscation` (a
    /// `plain: true` mesh link) must still emit real, explicit attributes - never nothing - since
    /// AmneziaWG's `SetDevice` treats an omitted attribute as "leave the kernel's current value
    /// alone", not "reset to default". The headers are the real WireGuard message types, not zero;
    /// the decoys and the header protection key are left out.
    #[test]
    fn default_obfuscation_still_pushes_every_junk_header_tuning_and_31_attribute() {
        use AmneziaWireguardAttribute as A;
        let unset = AmneziaWireguardRange::default();
        assert_eq!(
            push(&Obfuscation::default()),
            [
                A::Jc(0),
                A::Jmin(0),
                A::Jmax(0),
                A::S1(0),
                A::S2(0),
                A::S3(0),
                A::S4(0),
                A::H1(AmneziaWireguardRange::from(1)),
                A::H2(AmneziaWireguardRange::from(2)),
                A::H3(AmneziaWireguardRange::from(3)),
                A::H4(AmneziaWireguardRange::from(4)),
                A::ContentPaddingAddition(unset),
                A::RekeyAfterTime(unset),
                A::RekeyTimeout(unset),
                A::RejectAfterTime(unset),
                A::KeepaliveTimeout(unset),
                A::MaxHandshakeAttempts(unset),
                A::RandomTrailers(false),
                A::DisableCookies(false),
            ]
        );
    }

    #[test]
    fn stripping_the_31_attributes_leaves_everything_else_in_order_and_none_without_them() {
        let attrs = push(&Obfuscation::default());
        let stripped = without_31_attributes(&attrs).expect("3.1 attributes were present");
        assert_eq!(stripped, attrs[..attrs.len() - 2]);
        assert!(without_31_attributes(&[AmneziaWireguardAttribute::Jc(4)]).is_none());
    }

    #[test]
    fn every_obfuscation_value_set_is_sent_as_it_is() {
        use AmneziaWireguardAttribute as A;
        let key = [7; 32];
        let o = Obfuscation {
            jc: Some(4),
            jmin: Some(40),
            jmax: Some(70),
            s1: Some(11),
            s2: Some(12),
            s3: Some(13),
            s4: Some(14),
            h1: range("5-9"),
            h3: range("12345"),
            h4: range("4000000000-4294967295"),
            i1: Some("<b 0x01>".into()),
            i2: Some("<b 0x02>".into()),
            i3: Some("<b 0x03>".into()),
            i4: Some("<b 0x04>".into()),
            i5: Some("<b 0x05>".into()),
            header_protection_key: Some(encode_key(&key).as_str().into()),
            content_padding_addition: range("0-128"),
            rekey_after_time: range("120"),
            rekey_timeout: range("5-7"),
            reject_after_time: range("200-220"),
            keepalive_timeout: range("12"),
            max_handshake_attempts: range("20-65535"),
            random_trailers: Some(true),
            disable_cookies: Some(true),
            ..Obfuscation::default()
        };
        assert_eq!(
            push(&o),
            [
                A::Jc(4),
                A::Jmin(40),
                A::Jmax(70),
                A::S1(11),
                A::S2(12),
                A::S3(13),
                A::S4(14),
                A::H1(AmneziaWireguardRange { lo: 5, hi: 9 }),
                // Left unset, h2 keeps its own default whatever the others are.
                A::H2(AmneziaWireguardRange::from(2)),
                A::H3(AmneziaWireguardRange::from(12345)),
                A::H4(AmneziaWireguardRange {
                    lo: 4_000_000_000,
                    hi: 4_294_967_295,
                }),
                A::I1("<b 0x01>".into()),
                A::I2("<b 0x02>".into()),
                A::I3("<b 0x03>".into()),
                A::I4("<b 0x04>".into()),
                A::I5("<b 0x05>".into()),
                A::HeaderProtectionKey(key),
                A::ContentPaddingAddition(AmneziaWireguardRange { lo: 0, hi: 128 }),
                A::RekeyAfterTime(AmneziaWireguardRange::from(120)),
                A::RekeyTimeout(AmneziaWireguardRange { lo: 5, hi: 7 }),
                A::RejectAfterTime(AmneziaWireguardRange { lo: 200, hi: 220 }),
                A::KeepaliveTimeout(AmneziaWireguardRange::from(12)),
                A::MaxHandshakeAttempts(AmneziaWireguardRange { lo: 20, hi: 65535 }),
                A::RandomTrailers(true),
                A::DisableCookies(true),
            ]
        );
    }

    fn range<T: sliplib_config::End>(text: &str) -> Option<sliplib_config::Range<T>> {
        Some(text.parse().unwrap())
    }
}
