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

/// `field` is the caller's path to the section.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MetricsError {
    #[error("{field} {listen:?} is not an ip:port: {error}")]
    NotAnAddress {
        field: String,
        listen: String,
        error: std::net::AddrParseError,
    },
    #[error(
        "{field} {listen:?} is not IPv4 - Prometheus discovers a node by its InternalIP, which is the v4 loopback"
    )]
    NotIpv4 { field: String, listen: String },
    #[error(
        "{field} {listen:?} is a wildcard address - bind this node's own mesh loopback, which exists only inside the overlay"
    )]
    Wildcard { field: String, listen: String },
    #[error("{field} {listen:?} has no port - omit the section to serve nothing")]
    NoPort { field: String, listen: String },
}

impl MetricsConfig {
    pub fn validate(&self, field: &str) -> Result<(), MetricsError> {
        let (field, listen) = (field.to_owned(), self.listen.clone());
        let address: std::net::SocketAddr = match self.listen.parse() {
            Ok(address) => address,
            Err(error) => {
                return Err(MetricsError::NotAnAddress {
                    field,
                    listen,
                    error,
                });
            }
        };
        if !address.is_ipv4() {
            return Err(MetricsError::NotIpv4 { field, listen });
        }
        // Both parse and bind. A wildcard puts the endpoint on every interface, public ones too.
        if address.ip().is_unspecified() {
            return Err(MetricsError::Wildcard { field, listen });
        }
        // An ephemeral port nothing can be pointed at.
        if address.port() == 0 {
            return Err(MetricsError::NoPort { field, listen });
        }
        Ok(())
    }
}

fn metrics_valid(metrics: Option<&MetricsConfig>) -> Result<(), MetricsError> {
    metrics.map_or(Ok(()), |metrics| metrics.validate("metrics.listen"))
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

    #[test]
    fn accepts_a_v4_metrics_listen_address() {
        with_metrics("198.51.100.1:9586").validate().unwrap();
    }

    #[test]
    fn rejects_a_wildcard_metrics_listen_address() {
        assert!(with_metrics("0.0.0.0:9586").validate().is_err());
    }

    #[test]
    fn rejects_port_zero() {
        assert!(with_metrics("198.51.100.1:0").validate().is_err());
    }

    #[test]
    fn rejects_a_malformed_metrics_listen_address() {
        assert!(with_metrics("198.51.100.1").validate().is_err());
        assert!(with_metrics("not-an-address").validate().is_err());
    }

    #[test]
    fn rejects_a_v6_metrics_listen_address() {
        assert!(with_metrics("[3fff::1]:9586").validate().is_err());
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

    /// `router` asks for the check too.
    #[test]
    fn router_rejects_a_wildcard_metrics_listener() {
        let yaml = "node:\n  loopback_addresses: [\"198.51.100.1/32\", \"3fff::1/128\"]\nbgp_as: \
                    64512\nmetrics:\n  listen: 0.0.0.0:9324\n";
        let cfg: RouterDaemonConfig = sliplib_yaml::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("wildcard"), "unexpected error: {err}");
    }
}
