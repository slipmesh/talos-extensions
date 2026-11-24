//! The bodies of the `talos` `platform` document and of a `template`, which sliplib hands over as
//! written.

use crate::defaults::Service;
use serde::{Deserialize, Deserializer, de::Error as _};
use sliplib_config::v2::{self, File, Platform};
use std::num::NonZeroU16;

/// The body of the `talos` `platform` document.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct TalosSettings {
    #[serde(default, deserialize_with = "one_port_each")]
    pub metrics: Metrics,
}

impl TalosSettings {
    /// Default where the files hold no `talos` `platform` document.
    pub fn of(files: &File) -> Result<Self, v2::Error> {
        files
            .platform(Platform::Talos)
            .map_or(Ok(Self::default()), |document| document.read())
    }
}

/// An entry left out, no listener.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// The node's links.
    pub mesh: Option<Listener>,
    /// The node's routing.
    pub router: Option<Listener>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MetricsError {
    #[error(
        "`metrics.mesh` and `metrics.router` both take port {0}, and two daemons cannot serve one port - give each its own"
    )]
    OnePort(u16),
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    /// On the node's IPv4 loopback.
    pub port: NonZeroU16,
}

fn one_port_each<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Metrics, D::Error> {
    let metrics = Metrics::deserialize(deserializer)?;
    if let (Some(mesh), Some(router)) = (&metrics.mesh, &metrics.router)
        && mesh.port == router.port
    {
        return Err(D::Error::custom(MetricsError::OnePort(mesh.port.get())));
    }
    Ok(metrics)
}

/// The body of a `template` document.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub daemon: Service,
    pub base: Base,
    pub content: String,
}

/// The reference template a text was made from, by the SHA-256 of its text.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(try_from = "String")]
pub struct Base(String);

impl Base {
    /// In lower case, whatever case the files write.
    pub fn digest(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "`base` is `sha256:` and the 64 hexadecimal digits of the SHA-256 of the reference template, which {0:?} is not - `slipmesh-taloscfg template` prints the document with it"
)]
pub struct BaseError(String);

impl TryFrom<String> for Base {
    type Error = BaseError;

    fn try_from(text: String) -> Result<Self, BaseError> {
        match text.strip_prefix("sha256:") {
            Some(digest) if digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) => {
                Ok(Self(digest.to_ascii_lowercase()))
            }
            _ => Err(BaseError(text)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read<T: serde::de::DeserializeOwned>(yaml: &str) -> Result<T, String> {
        sliplib_yaml::from_str(yaml).map_err(|error| error.to_string())
    }

    #[test]
    fn two_listeners_on_one_port_are_refused_naming_it() {
        let refused = read::<TalosSettings>("metrics: {mesh: {port: 9586}, router: {port: 9586}}")
            .unwrap_err();
        assert!(
            refused.contains(&MetricsError::OnePort(9586).to_string()),
            "{refused}"
        );
    }

    const DIGEST: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn a_base_is_a_sha256_read_in_either_case_and_held_in_lower() {
        let upper = format!("sha256:{}", DIGEST.to_ascii_uppercase());
        assert_eq!(Base::try_from(upper).unwrap().digest(), DIGEST);
        for text in [
            DIGEST.to_owned(),
            format!("sha512:{DIGEST}"),
            format!("sha256:{}", &DIGEST[1..]),
            format!("sha256:{DIGEST}0"),
            format!("sha256:{}g", &DIGEST[1..]),
        ] {
            assert_eq!(Base::try_from(text.clone()), Err(BaseError(text)));
        }
    }
}
