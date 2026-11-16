//! Thin wrapper around `netlink-packet-amneziawg` + `genetlink` - talks the kernel
//! module's own genl family ("amneziawg", not "wireguard") directly rather than shelling out to
//! the `awg` CLI. This module only owns the raw `GetDevice`/`SetDevice` netlink transport;
//! interface/address/route management is `rt.rs` (a different netlink family).
//!
//! Ported from slipmesh-operators' `common::netlink::awg` -
//! functionally identical, just re-homed into a project with no Kubernetes dependency.

use crate::keys::decode_key;
use crate::obfuscation::Obfuscation;
use anyhow::{Context, Result};
use futures::StreamExt;
use genetlink::GenetlinkHandle;
use netlink_packet_amneziawg::AmneziaWireguardRange;
use netlink_packet_amneziawg::{
    AmneziaWireguardAttribute, AmneziaWireguardCmd, AmneziaWireguardMessage,
};
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;

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
/// `i1`..`i5` and `header_protection_key` stay omit-if-unset: the module has no value of them
/// that means "none" - an interface keeps a key it was given until it is created anew.
///
/// `h1`..`h4` are ranges of two `u32` ends; ours is the range from the single value to itself.
///
/// `content_padding_addition`/`rekey_after_time`/`rekey_timeout`/`reject_after_time`/
/// `keepalive_timeout`/`max_handshake_attempts` are ranges of two `u16` ends, out of which the
/// module draws. A number from the config goes out as the range from it to itself. They are
/// always sent, zero for an unset one: zero is the module's "not set", and an omitted attribute
/// would keep what an earlier config put there.
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
    attrs.push(AmneziaWireguardAttribute::H1(AmneziaWireguardRange::from(
        h1,
    )));
    attrs.push(AmneziaWireguardAttribute::H2(AmneziaWireguardRange::from(
        h2,
    )));
    attrs.push(AmneziaWireguardAttribute::H3(AmneziaWireguardRange::from(
        h3,
    )));
    attrs.push(AmneziaWireguardAttribute::H4(AmneziaWireguardRange::from(
        h4,
    )));
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
    let range_of = |value: Option<u16>| AmneziaWireguardRange::from(value.unwrap_or(0));
    attrs.push(AmneziaWireguardAttribute::ContentPaddingAddition(range_of(
        o.content_padding_addition,
    )));
    attrs.push(AmneziaWireguardAttribute::RekeyAfterTime(range_of(
        o.rekey_after_time,
    )));
    attrs.push(AmneziaWireguardAttribute::RekeyTimeout(range_of(
        o.rekey_timeout,
    )));
    attrs.push(AmneziaWireguardAttribute::RejectAfterTime(range_of(
        o.reject_after_time,
    )));
    attrs.push(AmneziaWireguardAttribute::KeepaliveTimeout(range_of(
        o.keepalive_timeout,
    )));
    attrs.push(AmneziaWireguardAttribute::MaxHandshakeAttempts(range_of(
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
        assert!(attrs.contains(&AmneziaWireguardAttribute::Jc(0)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::Jmin(0)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::Jmax(0)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::S1(0)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::S2(0)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::S3(0)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::S4(0)));
    }

    /// `h1..h4` default to WireGuard's own real per-packet-type magic values (`1..4`), not `0` -
    /// `0` would just be a different, still-wrong magic value, not "no header obfuscation". See
    /// `obfuscation::DEFAULT_MAGIC_HEADERS`'s doc comment for where `1..4` comes from.
    #[test]
    fn default_obfuscation_headers_are_the_real_wireguard_message_types_not_zero() {
        let attrs = push(&Obfuscation::default());
        assert!(
            attrs.contains(&AmneziaWireguardAttribute::H1(AmneziaWireguardRange::from(
                1
            )))
        );
        assert!(
            attrs.contains(&AmneziaWireguardAttribute::H2(AmneziaWireguardRange::from(
                2
            )))
        );
        assert!(
            attrs.contains(&AmneziaWireguardAttribute::H3(AmneziaWireguardRange::from(
                3
            )))
        );
        assert!(
            attrs.contains(&AmneziaWireguardAttribute::H4(AmneziaWireguardRange::from(
                4
            )))
        );
    }

    #[test]
    fn a_tuning_value_is_sent_as_the_range_of_that_one_value() {
        let attrs = push(&Obfuscation {
            content_padding_addition: Some(64),
            rekey_after_time: Some(120),
            rekey_timeout: Some(6),
            reject_after_time: Some(200),
            keepalive_timeout: Some(12),
            max_handshake_attempts: Some(20),
            ..Obfuscation::default()
        });
        for sent in [
            AmneziaWireguardAttribute::ContentPaddingAddition(AmneziaWireguardRange::from(64)),
            AmneziaWireguardAttribute::RekeyAfterTime(AmneziaWireguardRange::from(120)),
            AmneziaWireguardAttribute::RekeyTimeout(AmneziaWireguardRange::from(6)),
            AmneziaWireguardAttribute::RejectAfterTime(AmneziaWireguardRange::from(200)),
            AmneziaWireguardAttribute::KeepaliveTimeout(AmneziaWireguardRange::from(12)),
            AmneziaWireguardAttribute::MaxHandshakeAttempts(AmneziaWireguardRange::from(20)),
        ] {
            assert!(attrs.contains(&sent), "{sent:?} not in {attrs:?}");
        }
    }

    #[test]
    fn stripping_the_31_attributes_leaves_everything_else_in_order() {
        let attrs = push(&Obfuscation::default());
        let stripped = without_31_attributes(&attrs).expect("3.1 attributes were present");
        assert!(!stripped.iter().any(|a| matches!(
            a,
            AmneziaWireguardAttribute::RandomTrailers(_)
                | AmneziaWireguardAttribute::DisableCookies(_)
        )));
        assert_eq!(stripped.len(), attrs.len() - 2);
        assert!(stripped.contains(&AmneziaWireguardAttribute::Jc(0)));
    }

    #[test]
    fn stripping_reports_nothing_to_strip_when_the_31_attributes_are_absent() {
        let attrs = vec![AmneziaWireguardAttribute::Jc(4)];
        assert!(without_31_attributes(&attrs).is_none());
    }

    /// Same reasoning as the junk attributes above, applied to AmneziaWG 3.1's two device
    /// flags: an omitted attribute leaves the kernel's current value in place, so a link that
    /// once had them on would keep them on after they were dropped from the config.
    #[test]
    fn default_obfuscation_pushes_both_31_flags_explicitly_off() {
        let attrs = push(&Obfuscation::default());
        assert!(attrs.contains(&AmneziaWireguardAttribute::RandomTrailers(false)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::DisableCookies(false)));
    }

    #[test]
    fn explicit_31_flags_are_used_verbatim() {
        let o = Obfuscation {
            random_trailers: Some(true),
            disable_cookies: Some(true),
            ..Obfuscation::default()
        };
        let attrs = push(&o);
        assert!(attrs.contains(&AmneziaWireguardAttribute::RandomTrailers(true)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::DisableCookies(true)));
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
        assert!(attrs.contains(&AmneziaWireguardAttribute::Jc(4)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::Jmin(40)));
        assert!(attrs.contains(&AmneziaWireguardAttribute::Jmax(70)));
        assert!(
            attrs.contains(&AmneziaWireguardAttribute::H1(AmneziaWireguardRange::from(
                12345
            )))
        );
        // Untouched h2 still falls back to its own real default, independent of h1 being set.
        assert!(
            attrs.contains(&AmneziaWireguardAttribute::H2(AmneziaWireguardRange::from(
                2
            )))
        );
    }

    // An unset one of these is left out of the request: no value of it restores the module's
    // state for an interface that never had one.
    #[test]
    fn unset_decoy_specs_and_the_header_protection_key_are_omitted() {
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
    }

    // Zero is the module's "not set", and an omitted attribute keeps what the kernel holds.
    #[test]
    fn an_unset_tuning_value_is_sent_as_zero() {
        let attrs = push(&Obfuscation::default());
        use AmneziaWireguardAttribute as A;
        for expected in [
            A::ContentPaddingAddition(AmneziaWireguardRange::default()),
            A::RekeyAfterTime(AmneziaWireguardRange::default()),
            A::RekeyTimeout(AmneziaWireguardRange::default()),
            A::RejectAfterTime(AmneziaWireguardRange::default()),
            A::KeepaliveTimeout(AmneziaWireguardRange::default()),
            A::MaxHandshakeAttempts(AmneziaWireguardRange::default()),
        ] {
            assert!(attrs.contains(&expected), "{expected:?} not in {attrs:?}");
        }
    }
}
