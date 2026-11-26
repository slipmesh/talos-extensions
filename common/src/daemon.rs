//! A daemon's config: what every platform shares, and where it serves its metrics.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sliplib_config::awg::AwgConfig;
use sliplib_config::router::RouterConfig;
use std::net::SocketAddr;
use std::path::Path;

/// Where Talos mounts the config `taloscfg` writes for `awg`, and the only place `awg` reads one.
pub const AWG_CONFIG_PATH: &str = "/etc/talos-extensions/awg.yaml";
/// Where Talos mounts the config `taloscfg` writes for `router`, and the only place `router` reads
/// one.
pub const ROUTER_CONFIG_PATH: &str = "/etc/talos-extensions/router.yaml";

/// Where a daemon serves its Prometheus endpoint.
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct MetricsConfig {
    /// On the node's IPv4 loopback: inside the overlay alone, and kubelet's `InternalIP`, by which
    /// Prometheus finds the node.
    pub listen: SocketAddr,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MetricsError {
    #[error(
        "metrics.listen {0} is not IPv4 - Prometheus discovers a node by its InternalIP, which is the v4 loopback"
    )]
    NotIpv4(SocketAddr),
    #[error(
        "metrics.listen {0} is a wildcard address - bind this node's own mesh loopback, which exists only inside the overlay"
    )]
    Wildcard(SocketAddr),
    #[error("metrics.listen {0} has no port - omit the section to serve nothing")]
    NoPort(SocketAddr),
}

impl MetricsConfig {
    pub fn validate(&self) -> Result<(), MetricsError> {
        let listen = self.listen;
        if !listen.is_ipv4() {
            return Err(MetricsError::NotIpv4(listen));
        }
        // A wildcard puts the endpoint on every interface, public ones too.
        if listen.ip().is_unspecified() {
            return Err(MetricsError::Wildcard(listen));
        }
        // An ephemeral port nothing can be pointed at.
        if listen.port() == 0 {
            return Err(MetricsError::NoPort(listen));
        }
        Ok(())
    }
}

/// The config every platform shares, as sliplib validates it.
pub trait SharedConfig: DeserializeOwned {
    fn validate(&self) -> anyhow::Result<()>;
}

impl SharedConfig for AwgConfig {
    fn validate(&self) -> anyhow::Result<()> {
        Ok(sliplib_config::awg::validate(self)?)
    }
}

impl SharedConfig for RouterConfig {
    fn validate(&self) -> anyhow::Result<()> {
        Ok(sliplib_config::router::validate(self)?)
    }
}

/// A daemon's own keys, beside the shared ones.
#[derive(Deserialize)]
struct OwnKeys {
    metrics: Option<MetricsConfig>,
}

/// What the generator writes: [`DaemonConfig::read`] reads it back.
#[derive(Serialize, Debug, PartialEq)]
pub struct DaemonConfig<Shared> {
    #[serde(flatten)]
    pub mesh: Shared,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsConfig>,
}

pub type AwgDaemonConfig = DaemonConfig<AwgConfig>;
pub type RouterDaemonConfig = DaemonConfig<RouterConfig>;

impl<Shared: SharedConfig> DaemonConfig<Shared> {
    /// Read twice, the shared keys and the daemon's own, each from the text.
    pub fn read(path: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            mesh: sliplib_yaml::read::<Shared>(path)?,
            metrics: sliplib_yaml::read::<OwnKeys>(path)?.metrics,
        })
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.mesh.validate()?;
        Ok(self
            .metrics
            .as_ref()
            .map_or(Ok(()), MetricsConfig::validate)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTER: &str =
        "node:\n  loopback_addresses: [\"198.51.100.1/32\", \"3fff::1/128\"]\nbgp_as: 64496\n";

    fn metrics(listen: &str) -> Option<MetricsConfig> {
        Some(MetricsConfig {
            listen: listen.parse().unwrap(),
        })
    }

    #[test]
    fn a_listen_address_is_one_v4_address_with_a_port() {
        let valid = |listen: &str| metrics(listen).unwrap().validate();
        assert_eq!(valid("198.51.100.1:9586"), Ok(()));
        for (listen, refused) in [
            (
                "[3fff::1]:9586",
                MetricsError::NotIpv4 as fn(SocketAddr) -> MetricsError,
            ),
            ("0.0.0.0:9586", MetricsError::Wildcard),
            ("198.51.100.1:0", MetricsError::NoPort),
        ] {
            assert_eq!(valid(listen), Err(refused(listen.parse().unwrap())));
        }
    }

    /// `text` as a daemon's file.
    fn file(text: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), text).unwrap();
        file
    }

    #[test]
    fn what_the_generator_writes_for_each_daemon_reads_back_the_same() {
        let awg = AwgDaemonConfig {
            mesh: sliplib_yaml::from_str(
                "interfaces:\n  - {name: mesh-a, listen_port: 51820, addresses: [\"fe80::1/64\"], \
                 private_key: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}\n",
            )
            .unwrap(),
            metrics: metrics("198.51.100.1:9586"),
        };
        let written = file(&sliplib_yaml::to_string(&awg).unwrap());
        assert_eq!(AwgDaemonConfig::read(written.path()).unwrap(), awg);
        let router = RouterDaemonConfig {
            mesh: sliplib_yaml::from_str(ROUTER).unwrap(),
            metrics: metrics("198.51.100.1:9324"),
        };
        let written = file(&sliplib_yaml::to_string(&router).unwrap());
        assert_eq!(RouterDaemonConfig::read(written.path()).unwrap(), router);
    }

    #[test]
    fn a_config_without_a_metrics_section_parses_and_validates() {
        let cfg = AwgDaemonConfig::read(file("interfaces: []").path()).unwrap();
        assert_eq!(cfg.metrics, None);
        cfg.validate().unwrap();
    }

    #[test]
    fn each_daemon_refuses_a_shared_config_sliplib_refuses_and_a_wildcard_listener() {
        let refusal = |cfg: anyhow::Result<()>| cfg.unwrap_err();
        let awg =
            |text: &str| refusal(AwgDaemonConfig::read(file(text).path()).unwrap().validate());
        let router = |text: &str| {
            refusal(
                RouterDaemonConfig::read(file(text).path())
                    .unwrap()
                    .validate(),
            )
        };
        let unnamed = awg(
            "interfaces:\n  - {name: \"\", listen_port: 51820, addresses: [], \
                           private_key: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}\n",
        );
        assert!(
            matches!(
                unnamed.downcast_ref(),
                Some(sliplib_config::awg::Invalid::EmptyInterfaceName)
            ),
            "{unnamed}"
        );
        let as_zero = router(&ROUTER.replace("bgp_as: 64496", "bgp_as: 0"));
        assert!(
            matches!(
                as_zero.downcast_ref(),
                Some(sliplib_config::router::Invalid::BgpAsZero)
            ),
            "{as_zero}"
        );

        let wildcard = "metrics:\n  listen: 0.0.0.0:9324\n";
        for err in [
            awg(&format!("interfaces: []\n{wildcard}")),
            router(&format!("{ROUTER}{wildcard}")),
        ] {
            assert!(
                matches!(err.downcast_ref(), Some(MetricsError::Wildcard(_))),
                "{err}"
            );
        }
    }
}
