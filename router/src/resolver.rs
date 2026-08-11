//! Resolution pipeline: resolve each source (asn -> RIPEstat, literal -> verbatim, geoip ->
//! RIPEstat, dns -> A record) into (net, label) pairs, dedupe/collapse per label, then punch out
//! every excluded network (resolved the same way). Ported from `slipmesh/core`'s `resolver.rs`
//! (github.com/slipmesh/core) - that module has no `kube`/`k8s-openapi` import (confirmed before
//! porting), so this is close to verbatim; the only structural change is `BypassSourceEntry`
//! below, a plain `#[derive(Deserialize)]` struct read straight out of `router.yaml` instead of
//! the CRD-schema'd version in `core/src/router_types.rs` (which derives `JsonSchema`/
//! `CustomResource` via `kube`'s macros - exactly the dependency this repo's `AGENTS.md` forbids).
//!
//! One behavioral change versus the k8s original, worth calling out explicitly rather than
//! silently dropping: `core::resolver::self_and_cluster_exclude_entry` isn't ported. It punched
//! every cluster node's own endpoint out of the bypass automatically, sourced from every
//! `NodeConfig` - there's no cluster-wide node list available to a static, per-node config file.
//! Whoever authors `router.yaml`'s `bypass.exclude` is responsible for excluding this node's own
//! (and any peer's) public endpoint if it could otherwise fall inside `bypass.include`, the same
//! "config-authoring concern" pattern `awg`'s README already documents for private keys.

use crate::cidr::{self, Cidr};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::sync::Semaphore;

/// One bypass-prefix source, resolved into concrete CIDRs by `collect_source`: `asn` via
/// RIPEstat's announced-prefixes API, `literal` verbatim, `geoip` via RIPEstat's
/// country-resource-list, `dns` via a live A-record lookup.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct BypassSourceEntry {
    /// "asn" | "literal" | "geoip" | "dns" - validated in `collect_source`/`config::validate`,
    /// not by the deserializer (a tagged enum would fit, but this mirrors the CRD original's
    /// four-way, mostly-optional-fields shape closely enough that keeping it a plain string keeps
    /// the two implementations easy to diff against each other).
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asns: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefixes: Option<Vec<LabeledPrefix>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// "dns" only - resolved via a live A-record lookup at resolve time, on the same
    /// startup/refresh-interval schedule as everything else. Whole list shares `label`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostnames: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct LabeledPrefix {
    pub net: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Per-call ceiling for one RIPEstat request or one DNS lookup. `reqwest`'s default is *no*
/// request timeout at all unless configured, hence `RIPESTAT_CLIENT` below.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(15);

/// Ceiling on one whole `resolve()` call, not just its individual requests - see `core::resolver`'s
/// original doc comment for the full reasoning (a caller typically holds some render lock across
/// this whole call).
pub const RESOLVE_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);

/// One shared client for every RIPEstat call - connection/TLS reuse across the lookups a single
/// resolve makes, instead of a fresh connection pool and TLS handshake per request.
///
/// Fallible rather than `.expect()`-built: building the TLS backend can fail on its own (confirmed
/// directly - this used to be an unconditional `.expect()` that panicked the whole process the
/// moment this extension's rootfs had nowhere for `rustls-platform-verifier` to find a CA store; see
/// `../../extension-services/router.yaml`'s `mounts:`, which bind-mounts the Talos host's own
/// `/etc/ssl/certs` into the container to fix that at the packaging level rather than here), and a
/// `LazyLock` initializer panicking on first access would take down this whole process rather than
/// just this bypass resolution attempt - exactly what `current_bypass_routes`'s retry/
/// last-known-good-cache handling above exists to avoid.
static RIPESTAT_CLIENT: LazyLock<reqwest::Result<reqwest::Client>> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(NETWORK_TIMEOUT)
        .user_agent("talos-extensions-router")
        .build()
});

fn parse_cidr(s: &str) -> Option<Cidr> {
    let (addr, len) = cidr::parse_cidr(s).ok()?;
    Some((u32::from(addr), len))
}

fn format_cidr((addr, len): Cidr) -> String {
    format!("{}/{len}", Ipv4Addr::from(addr))
}

/// RIPEstat's documented limit is 8 concurrent requests per IP
/// (https://stat.ripe.net/docs/02.data-api/); kept comfortably under that cap.
static RIPESTAT_CONCURRENCY: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(5));

/// RIPEstat's suggested self-identification query param. Required format: alphanumeric plus
/// hyphens/underscores only, no whitespace.
const RIPESTAT_SOURCEAPP: &str = "talos-extensions-router";

async fn ripestat_get(url: &str) -> Result<serde_json::Value> {
    let client = RIPESTAT_CLIENT
        .as_ref()
        .map_err(|e| anyhow::anyhow!("failed to build RIPEstat HTTP client: {e}"))?;
    let _permit = RIPESTAT_CONCURRENCY
        .acquire()
        .await
        .expect("RIPESTAT_CONCURRENCY semaphore is never closed");
    client
        .get(format!("{url}&sourceapp={RIPESTAT_SOURCEAPP}"))
        .send()
        .await
        .with_context(|| format!("RIPEstat request to {url} failed"))?
        .error_for_status()
        .context("RIPEstat returned an error status")?
        .json()
        .await
        .context("failed to parse RIPEstat response as JSON")
}

/// Validates RIPEstat's expected ASN format (`AS` followed by digits, e.g. `"AS15169"`) before
/// it's spliced into a request URL - a malformed value here isn't just a confusing upstream
/// error, it's unvalidated config input reaching a query string (e.g. `"AS123&foo=bar"` would
/// inject an extra query parameter into the RIPEstat request).
fn validate_asn(asn: &str) -> Result<()> {
    let digits = asn
        .strip_prefix("AS")
        .with_context(|| format!("ASN {asn:?} must start with \"AS\""))?;
    anyhow::ensure!(
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
        "ASN {asn:?} is not in the expected AS<digits> format"
    );
    Ok(())
}

/// Every IPv4 prefix `asn` (e.g. `"AS15169"`) actually announces, via RIPEstat's
/// announced-prefixes API - IPv6 entries are dropped (IPv4-only scope, see this module's own
/// doc comment).
async fn asn_prefixes(asn: &str) -> Result<Vec<String>> {
    validate_asn(asn)?;
    let url = format!("https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}");
    let resp = ripestat_get(&url).await?;
    let prefixes = resp
        .pointer("/data/prefixes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| entry.get("prefix")?.as_str())
                .filter(|p| !p.contains(':'))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(prefixes)
}

/// Validates ISO 3166-1 alpha-2 format (exactly two ASCII letters) before it's spliced into a
/// request URL - same rationale as `validate_asn`. Returns the normalized (uppercase) code.
fn validate_country(country: &str) -> Result<String> {
    anyhow::ensure!(
        country.len() == 2 && country.bytes().all(|b| b.is_ascii_alphabetic()),
        "country {country:?} is not a valid ISO 3166-1 alpha-2 code"
    );
    Ok(country.to_ascii_uppercase())
}

/// Every IPv4 block RIPE NCC has allocated/assigned to `country` (ISO 3166-1 alpha-2), via
/// RIPEstat's country-resource-list API - the same registry data every GeoIP database derives
/// from.
async fn geoip_country_prefixes(country: &str) -> Result<Vec<String>> {
    let url =
        format!("https://stat.ripe.net/data/country-resource-list/data.json?resource={country}");
    let resp = ripestat_get(&url).await?;
    let prefixes = resp
        .pointer("/data/resources/ipv4")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(prefixes)
}

async fn collect_source(source: &BypassSourceEntry) -> Result<Vec<(String, String)>> {
    match source.kind.as_str() {
        "literal" => {
            let prefixes = source
                .prefixes
                .as_ref()
                .context("literal source requires `prefixes`")?;
            Ok(prefixes
                .iter()
                .map(|p| (p.net.clone(), p.label.clone().unwrap_or_default()))
                .collect())
        }
        "asn" => {
            let label = source
                .label
                .clone()
                .context("asn source requires `label`")?;
            let asns = source.asns.as_ref().context("asn source requires `asns`")?;
            let routes_per_asn =
                futures::future::try_join_all(asns.iter().map(|asn| asn_prefixes(asn))).await?;
            Ok(routes_per_asn
                .into_iter()
                .flatten()
                .map(|route| (route, label.clone()))
                .collect())
        }
        "dns" => {
            let label = source
                .label
                .clone()
                .context("dns source requires `label`")?;
            let hostnames = source
                .hostnames
                .as_ref()
                .context("dns source requires `hostnames`")?;
            let mut entries = Vec::new();
            for host in hostnames {
                let addrs = tokio::time::timeout(
                    NETWORK_TIMEOUT,
                    tokio::net::lookup_host((host.as_str(), 0)),
                )
                .await
                .with_context(|| {
                    format!("DNS lookup for {host} timed out after {NETWORK_TIMEOUT:?}")
                })?
                .with_context(|| format!("DNS lookup failed for {host}"))?;
                for addr in addrs {
                    if let std::net::SocketAddr::V4(v4) = addr {
                        entries.push((format!("{}/32", v4.ip()), label.clone()));
                    }
                }
            }
            Ok(entries)
        }
        "geoip" => {
            let country = source
                .country
                .clone()
                .context("geoip source requires `country`")?;
            let country = validate_country(&country)?;
            let label = source
                .label
                .clone()
                .unwrap_or_else(|| format!("geoip {country}"));
            Ok(geoip_country_prefixes(&country)
                .await?
                .into_iter()
                .map(|p| (p, label.clone()))
                .collect())
        }
        other => anyhow::bail!("unknown bypass source kind: {other:?}"),
    }
}

/// Dedupe exact-duplicate CIDRs (first label wins), group by label, collapse each label's set
/// independently - a merge never crosses label/org boundaries.
fn dedupe_and_aggregate(entries: Vec<(String, String)>) -> Vec<(Cidr, String)> {
    let mut by_net: std::collections::BTreeMap<Cidr, String> = std::collections::BTreeMap::new();
    for (cidr_str, label) in entries {
        let Some(cidr) = parse_cidr(&cidr_str) else {
            tracing::warn!(cidr = cidr_str, "skipping malformed CIDR in bypass source");
            continue;
        };
        by_net.entry(cidr).or_insert(label);
    }
    let mut by_label: std::collections::BTreeMap<String, Vec<Cidr>> =
        std::collections::BTreeMap::new();
    for (cidr, label) in by_net {
        by_label.entry(label).or_default().push(cidr);
    }
    let mut result = Vec::new();
    for (label, nets) in by_label {
        for net in cidr::collapse(&nets) {
            result.push((net, label.clone()));
        }
    }
    result.sort();
    result
}

async fn resolve_entries(sources: &[BypassSourceEntry]) -> Result<Vec<(Cidr, String)>> {
    let per_source = futures::future::try_join_all(sources.iter().map(collect_source)).await?;
    Ok(dedupe_and_aggregate(
        per_source.into_iter().flatten().collect(),
    ))
}

/// Full pipeline: resolve `sources` and `exclude` (identical resolution logic for both, via
/// `resolve_entries`), then punch every exclusion out of every included prefix.
///
/// Any resolution failure fails the whole call rather than returning a partial result - see
/// `core::resolver::resolve`'s original doc comment for the full "fails closed, toward 'no
/// blackholing'" reasoning, which applies unchanged here.
pub async fn resolve(
    sources: &[BypassSourceEntry],
    exclude: &[BypassSourceEntry],
) -> Result<Vec<(String, String)>> {
    tokio::time::timeout(RESOLVE_TOTAL_TIMEOUT, resolve_inner(sources, exclude))
        .await
        .with_context(|| {
            format!("bypass resolution exceeded its total budget of {RESOLVE_TOTAL_TIMEOUT:?}")
        })?
}

async fn resolve_inner(
    sources: &[BypassSourceEntry],
    exclude: &[BypassSourceEntry],
) -> Result<Vec<(String, String)>> {
    let included = resolve_entries(sources).await?;
    anyhow::ensure!(
        !included.is_empty(),
        "computed zero prefixes from sources - a source likely failed to resolve, refusing to \
         return an empty bypass"
    );

    let mut exclude_nets: Vec<Cidr> = resolve_entries(exclude)
        .await?
        .into_iter()
        .map(|(net, _label)| net)
        .collect();
    exclude_nets = cidr::collapse(&exclude_nets);

    let mut out = Vec::new();
    for (net, label) in included {
        let mut pending = vec![net];
        for &exc in &exclude_nets {
            let mut next_pending = Vec::new();
            for n in pending {
                if cidr::contains(exc, n) {
                    continue;
                }
                if cidr::contains(n, exc) {
                    next_pending.extend(cidr::address_exclude(n, exc));
                } else {
                    next_pending.push(n);
                }
            }
            pending = next_pending;
        }
        for n in pending {
            out.push((format_cidr(n), label.clone()));
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_asn_accepts_well_formed() {
        assert!(validate_asn("AS15169").is_ok());
        assert!(validate_asn("AS1").is_ok());
    }

    #[test]
    fn validate_asn_rejects_missing_prefix() {
        assert!(validate_asn("15169").is_err());
    }

    #[test]
    fn validate_asn_rejects_non_digit_suffix() {
        assert!(validate_asn("AS").is_err());
        assert!(validate_asn("ASxyz").is_err());
    }

    #[test]
    fn validate_asn_rejects_query_string_injection() {
        assert!(validate_asn("AS123&foo=bar").is_err());
    }

    #[test]
    fn validate_country_accepts_two_letter_codes_either_case() {
        assert_eq!(validate_country("DE").unwrap(), "DE");
        assert_eq!(validate_country("de").unwrap(), "DE");
    }

    #[test]
    fn validate_country_rejects_wrong_length() {
        assert!(validate_country("D").is_err());
        assert!(validate_country("DEU").is_err());
    }

    #[test]
    fn validate_country_rejects_non_alphabetic() {
        assert!(validate_country("D1").is_err());
        assert!(validate_country("DE&foo=bar").is_err());
    }

    #[test]
    fn bypass_source_entry_parses_from_yaml() {
        let yaml = r#"
kind: asn
label: "some vendor"
asns: ["AS15169"]
"#;
        let entry: BypassSourceEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.kind, "asn");
        assert_eq!(entry.asns, Some(vec!["AS15169".to_string()]));
    }
}
