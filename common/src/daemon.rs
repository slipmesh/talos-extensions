//! A daemon's config: what every platform shares, and where it serves its metrics.

use serde::{Deserialize, Serialize};
use sliplib_config::awg::AwgConfig;
use sliplib_config::router::RouterConfig;

/// Where a daemon serves its Prometheus endpoint.
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct MetricsConfig {
    /// `ip:port` on the node's IPv4 loopback: inside the overlay alone, and kubelet's `InternalIP`,
    /// by which Prometheus finds the node.
    pub listen: String,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MetricsError {
    #[error("metrics.listen {listen:?} is not an ip:port: {error}")]
    NotAnAddress {
        listen: String,
        error: std::net::AddrParseError,
    },
    #[error(
        "metrics.listen {0:?} is not IPv4 - Prometheus discovers a node by its InternalIP, which is the v4 loopback"
    )]
    NotIpv4(String),
    #[error(
        "metrics.listen {0:?} is a wildcard address - bind this node's own mesh loopback, which exists only inside the overlay"
    )]
    Wildcard(String),
    #[error("metrics.listen {0:?} has no port - omit the section to serve nothing")]
    NoPort(String),
}

impl MetricsConfig {
    pub fn validate(&self) -> Result<(), MetricsError> {
        let listen = self.listen.clone();
        let address: std::net::SocketAddr = match self.listen.parse() {
            Ok(address) => address,
            Err(error) => return Err(MetricsError::NotAnAddress { listen, error }),
        };
        if !address.is_ipv4() {
            return Err(MetricsError::NotIpv4(listen));
        }
        // Both parse and bind. A wildcard puts the endpoint on every interface, public ones too.
        if address.ip().is_unspecified() {
            return Err(MetricsError::Wildcard(listen));
        }
        // An ephemeral port nothing can be pointed at.
        if address.port() == 0 {
            return Err(MetricsError::NoPort(listen));
        }
        Ok(())
    }
}

fn metrics_valid(metrics: Option<&MetricsConfig>) -> Result<(), MetricsError> {
    metrics.map_or(Ok(()), MetricsConfig::validate)
}

#[derive(Deserialize, Serialize, Debug, Default, PartialEq)]
pub struct AwgDaemonConfig {
    #[serde(flatten)]
    pub mesh: AwgConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsConfig>,
}

impl AwgDaemonConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        sliplib_config::awg::validate(&self.mesh)?;
        Ok(metrics_valid(self.metrics.as_ref())?)
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct RouterDaemonConfig {
    #[serde(flatten)]
    pub mesh: RouterConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsConfig>,
}

impl RouterDaemonConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        sliplib_config::router::validate(&self.mesh)?;
        Ok(metrics_valid(self.metrics.as_ref())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_metrics(listen: &str) -> AwgDaemonConfig {
        AwgDaemonConfig {
            metrics: Some(MetricsConfig {
                listen: listen.to_string(),
            }),
            ..AwgDaemonConfig::default()
        }
    }

    fn refusal(listen: &str) -> MetricsError {
        MetricsConfig {
            listen: listen.to_owned(),
        }
        .validate()
        .unwrap_err()
    }

    #[test]
    fn accepts_a_v4_metrics_listen_address() {
        with_metrics("198.51.100.1:9586").validate().unwrap();
    }

    #[test]
    fn a_listen_address_that_is_not_one_v4_address_with_a_port_is_refused_saying_why() {
        for (listen, refused) in [
            (
                "198.51.100.1",
                "metrics.listen \"198.51.100.1\" is not an ip:port: invalid socket address syntax",
            ),
            (
                "not-an-address",
                "metrics.listen \"not-an-address\" is not an ip:port: invalid socket address syntax",
            ),
            (
                "[3fff::1]:9586",
                "metrics.listen \"[3fff::1]:9586\" is not IPv4 - Prometheus discovers a node by its \
                 InternalIP, which is the v4 loopback",
            ),
            (
                "0.0.0.0:9586",
                "metrics.listen \"0.0.0.0:9586\" is a wildcard address - bind this node's own mesh \
                 loopback, which exists only inside the overlay",
            ),
            (
                "198.51.100.1:0",
                "metrics.listen \"198.51.100.1:0\" has no port - omit the section to serve nothing",
            ),
        ] {
            assert_eq!(refusal(listen).to_string(), refused);
        }
        assert!(matches!(
            refusal("198.51.100.1"),
            MetricsError::NotAnAddress { .. }
        ));
        assert!(matches!(
            refusal("[3fff::1]:9586"),
            MetricsError::NotIpv4(_)
        ));
        assert!(matches!(refusal("0.0.0.0:9586"), MetricsError::Wildcard(_)));
        assert!(matches!(refusal("198.51.100.1:0"), MetricsError::NoPort(_)));
    }

    #[test]
    fn a_config_without_a_metrics_section_parses_and_validates() {
        let cfg: AwgDaemonConfig = sliplib_yaml::from_str("interfaces: []").unwrap();
        assert_eq!(cfg.metrics, None);
        cfg.validate().unwrap();
    }

    #[test]
    fn a_metrics_section_round_trips_through_yaml() {
        let cfg = with_metrics("198.51.100.1:9586");
        let yaml = sliplib_yaml::to_string(&cfg).unwrap();
        assert_eq!(
            sliplib_yaml::from_str::<AwgDaemonConfig>(&yaml).unwrap(),
            cfg
        );
    }

    #[test]
    fn awg_rejects_a_wildcard_metrics_listener() {
        let err = with_metrics("0.0.0.0:9586").validate().unwrap_err();
        assert!(err.to_string().contains("wildcard"), "{err}");
    }

    #[test]
    fn router_rejects_a_wildcard_metrics_listener() {
        let yaml = "node:\n  loopback_addresses: [\"198.51.100.1/32\", \"3fff::1/128\"]\nbgp_as: \
                    64512\nmetrics:\n  listen: 0.0.0.0:9324\n";
        let cfg: RouterDaemonConfig = sliplib_yaml::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("wildcard"), "unexpected error: {err}");
    }
}
