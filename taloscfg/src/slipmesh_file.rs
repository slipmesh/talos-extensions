//! `slipmesh.yaml`: what each document in it is, which hosts it reaches, and what one host ends up
//! with.
//!
//! Every document carries a `slipmesh:` block saying what it is for. `network` is the topology,
//! exactly one of it. `roadwarriors` is one pool per document. `nftables` is a ruleset, and
//! `patch` is a Talos document, both aimed at hosts by `include`/`exclude`. The block is addressed
//! to this tool and never reaches a patch file.

use crate::document;
use crate::merge::merge_document;
use crate::mesh_config::{self, MeshConfig, NftablesTopology, RoadwarriorPool};
use crate::segments::OWNED_NAMES;
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::ops::Range;
use yaml_serde::Value;

#[derive(Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Network,
    Roadwarriors,
    Nftables,
    Patch,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Network => "network",
            Kind::Roadwarriors => "roadwarriors",
            Kind::Nftables => "nftables",
            Kind::Patch => "patch",
        }
    }
}

/// A document's `slipmesh:` block. Strict, so that a misspelled `include` is an error rather than
/// a document that silently reaches every host.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    kind: Kind,
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
}

struct Document {
    line: usize,
    /// The document's bytes in the file, markers and all - where an edited version goes back.
    span: Range<usize>,
    meta: Meta,
    /// Trimmed, without document markers or the `slipmesh:` block - what a patch file gets when
    /// nothing is merged into it.
    text: String,
    /// The same document parsed, also without the `slipmesh:` block.
    value: Value,
    /// The document's own bytes with the `slipmesh:` block blanked out, behind as many empty lines
    /// as come before it in the file - deserialized from this, a document's error names the line
    /// of the file it is on.
    positioned: String,
}

impl Document {
    /// `None` for a document with nothing in it but comments: it says nothing to route.
    ///
    /// The value is parsed from `exact`, the document's own bytes, and not from the trimmed
    /// `text`: trimming takes the final newline off a block scalar that ends the document, and
    /// with it changes the scalar's value.
    fn read(exact: &str, span: Range<usize>, text: &str, line: usize) -> Result<Option<Self>> {
        let mut value: Value = yaml_serde::from_str(exact).context("not valid YAML")?;
        if value.is_null() {
            return Ok(None);
        }
        let meta = value
            .as_mapping_mut()
            .and_then(|mapping| mapping.shift_remove(document::META_KEY))
            .context("no `slipmesh:` block saying what the document is for")?;
        let meta: Meta = yaml_serde::from_value(meta).context("its `slipmesh:` block")?;
        let text = document::strip_meta(text)?.trim().to_owned();
        let positioned = "\n".repeat(line - 1) + &document::blank_key(exact, document::META_KEY)?;
        Ok(Some(Self {
            line,
            span,
            meta,
            text,
            value,
            positioned,
        }))
    }

    /// The document as `T`, with an error that names the field and the line of the file.
    fn deserialize<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        yaml_serde::from_str(&self.positioned).with_context(|| self.at())
    }

    fn at(&self) -> String {
        format!(
            "the `kind: {}` document at line {}",
            self.meta.kind.name(),
            self.line
        )
    }

    fn reaches(&self, host: &str) -> bool {
        self.meta
            .include
            .as_ref()
            .is_none_or(|hosts| hosts.iter().any(|h| h == host))
            && !self.meta.exclude.iter().flatten().any(|h| h == host)
    }
}

/// One Talos document as it goes into one host's patch file.
#[derive(Debug, PartialEq)]
pub struct HostDocument {
    /// `kind`, plus `/name` when the document has one - what a warning calls it.
    pub identity: String,
    pub text: String,
    /// How many `patch` documents it was merged from. More than one means it was re-serialized,
    /// which loses its comments.
    pub sources: usize,
}

pub struct SlipmeshFile {
    network: Value,
    hosts: Vec<String>,
    pools: Vec<Document>,
    rulesets: Vec<Document>,
    patches: Vec<Document>,
}

impl SlipmeshFile {
    pub fn parse(raw: &str) -> Result<Self> {
        let mut networks = Vec::new();
        let mut pools = Vec::new();
        let mut rulesets = Vec::new();
        let mut patches = Vec::new();
        for (span, text) in document::documents(raw)? {
            let line = raw[..span.start].matches('\n').count() + 1;
            let Some(document) = Document::read(&raw[span.clone()], span.clone(), &text, line)
                .with_context(|| format!("the document starting at line {line}"))?
            else {
                continue;
            };
            match document.meta.kind {
                Kind::Network => networks.push(document),
                Kind::Roadwarriors => pools.push(document),
                Kind::Nftables => rulesets.push(document),
                Kind::Patch => patches.push(document),
            }
        }

        ensure!(
            networks.len() == 1,
            "slipmesh.yaml needs exactly one `kind: network` document, found {}",
            networks.len()
        );
        let network = networks.remove(0);
        for untargeted in std::iter::once(&network).chain(&pools) {
            ensure!(
                untargeted.meta.include.is_none() && untargeted.meta.exclude.is_none(),
                "{}: `include`/`exclude` aim a document at hosts, and this kind is not aimed",
                untargeted.at()
            );
        }
        for (section, kind) in [
            ("roadwarriors", Kind::Roadwarriors),
            ("nftables", Kind::Nftables),
        ] {
            ensure!(
                network.value.get(section).is_none(),
                "{}: `{section}` belongs in its own `kind: {}` document",
                network.at(),
                kind.name()
            );
        }
        let topology: MeshConfig = network.deserialize()?;
        let hosts: Vec<String> = topology.nodes.into_iter().map(|n| n.name).collect();

        for targeted in rulesets.iter().chain(&patches) {
            if let Some(include) = &targeted.meta.include {
                ensure!(
                    !include.is_empty(),
                    "{}: `include: []` reaches no host - leave `include` out to reach every host",
                    targeted.at()
                );
            }
            for host in targeted
                .meta
                .include
                .iter()
                .chain(&targeted.meta.exclude)
                .flatten()
            {
                ensure!(
                    hosts.contains(host),
                    "{}: names host {host:?}, which the network document does not have",
                    targeted.at()
                );
            }
        }

        for pool in &pools {
            pool.deserialize::<RoadwarriorPool>()?;
        }
        for ruleset in &rulesets {
            ruleset.deserialize::<NftablesTopology>()?;
        }
        for host in &hosts {
            let lines: Vec<String> = rulesets
                .iter()
                .filter(|r| r.reaches(host))
                .map(|r| r.line.to_string())
                .collect();
            ensure!(
                lines.len() <= 1,
                "host {host:?} is reached by the `kind: nftables` documents at lines {} - a \
                 ruleset is one text, and two cannot be merged",
                lines.join(", ")
            );
        }

        for patch in &patches {
            let identity = Identity::of(&patch.value);
            let Some(kind) = &identity.kind else {
                bail!(
                    "{}: has no Talos `kind`, so it has no identity to merge by - a bare \
                     `machine:` belongs in patch-common.yaml",
                    patch.at()
                );
            };
            if let Some(name) = &identity.name
                && kind == "ExtensionServiceConfig"
                && OWNED_NAMES.contains(&name.as_str())
            {
                bail!(
                    "{}: `ExtensionServiceConfig` {name:?} is generated from the network, not \
                     written by hand",
                    patch.at()
                );
            }
        }

        let parsed = Self {
            network: network.value,
            hosts,
            pools,
            rulesets,
            patches,
        };
        parsed.topology()?;
        Ok(parsed)
    }

    /// The byte range of the `roadwarriors` document holding pool `name` - where an edit to that
    /// pool is spliced back.
    pub fn pool_span(&self, name: &str) -> Option<Range<usize>> {
        self.pools
            .iter()
            .find(|p| p.value.get("name").and_then(Value::as_str) == Some(name))
            .map(|p| p.span.clone())
    }

    /// The hosts `network` names, in its order.
    pub fn hosts(&self) -> Vec<&str> {
        self.hosts.iter().map(String::as_str).collect()
    }

    /// The whole topology: `network` with every pool, and no ruleset - the ruleset differs by host
    /// and plays no part in anything shared between them, such as secrets.
    pub fn topology(&self) -> Result<MeshConfig> {
        self.model(None)
    }

    /// The topology as one host sees it: with the ruleset aimed at that host, if any.
    pub fn effective_for(&self, host: &str) -> Result<MeshConfig> {
        self.ensure_host(host)?;
        let ruleset = self.rulesets.iter().find(|r| r.reaches(host));
        self.model(ruleset.map(|r| r.value.clone()))
    }

    /// The Talos documents that go into `host`'s patch file, in the order their identities first
    /// appear.
    ///
    /// Documents of one identity are merged defaults first, then those naming the host in
    /// `include`, each in file order - so the more specific document wins wherever it sits in the
    /// file.
    pub fn patches_for(&self, host: &str) -> Result<Vec<HostDocument>> {
        self.ensure_host(host)?;
        let reaching: Vec<&Document> = self.patches.iter().filter(|p| p.reaches(host)).collect();

        let mut identities: Vec<Identity> = Vec::new();
        for patch in &reaching {
            let identity = Identity::of(&patch.value);
            if !identities.contains(&identity) {
                identities.push(identity);
            }
        }

        identities
            .into_iter()
            .map(|identity| {
                let defaults = reaching.iter().filter(|p| p.meta.include.is_none());
                let included = reaching.iter().filter(|p| p.meta.include.is_some());
                let sources: Vec<&Document> = defaults
                    .chain(included)
                    .filter(|p| Identity::of(&p.value) == identity)
                    .copied()
                    .collect();
                let text = match sources.as_slice() {
                    [only] => only.text.clone(),
                    [first, rest @ ..] => {
                        let merged = rest.iter().fold(first.value.clone(), |base, patch| {
                            merge_document(base, &patch.value)
                        });
                        yaml_serde::to_string(&merged)
                            .context("serializing a merged patch")?
                            .trim_end()
                            .to_owned()
                    }
                    [] => unreachable!("every identity comes from at least one document"),
                };
                Ok(HostDocument {
                    identity: identity.to_string(),
                    text,
                    sources: sources.len(),
                })
            })
            .collect()
    }

    fn ensure_host(&self, host: &str) -> Result<()> {
        ensure!(
            self.hosts.iter().any(|h| h == host),
            "host {host:?} is not in the network document"
        );
        Ok(())
    }

    fn model(&self, ruleset: Option<Value>) -> Result<MeshConfig> {
        let mut value = self.network.clone();
        let mapping = value
            .as_mapping_mut()
            .context("the network document is not a mapping")?;
        let pools = self.pools.iter().map(|p| p.value.clone()).collect();
        mapping.insert("roadwarriors".into(), Value::Sequence(pools));
        if let Some(ruleset) = ruleset {
            mapping.insert("nftables".into(), ruleset);
        }
        let model: MeshConfig = yaml_serde::from_value(value).context("assembling the topology")?;
        mesh_config::validate(&model)?;
        Ok(model)
    }
}

/// What Talos keys a document by - two `patch` documents with the same one are merged.
#[derive(PartialEq)]
struct Identity {
    api_version: Option<String>,
    kind: Option<String>,
    name: Option<String>,
}

impl Identity {
    fn of(value: &Value) -> Self {
        let field = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
        Self {
            api_version: field("apiVersion"),
            kind: field("kind"),
            name: field("name"),
        }
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind.as_deref().unwrap_or_default())?;
        if let Some(name) = &self.name {
            write!(f, "/{name}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: &str = r#"slipmesh:
  kind: network
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
nodes:
  - {name: node-a, node_id: "10.62.0.1"}
  - {name: node-b, node_id: "10.62.0.2"}
  - {name: node-c, node_id: "10.62.0.3"}
"#;

    const KUBELET: &str = r#"slipmesh:
  kind: patch
apiVersion: v1alpha1
kind: KubeletConfig
extraArgs:
    rotate-server-certificates: "true"
"#;

    fn file(documents: &[&str]) -> String {
        documents.join("---\n")
    }

    fn pool(name: &str, port: u16) -> String {
        format!(
            "slipmesh:\n  kind: roadwarriors\nname: {name}\nnode_hostnames: [node-a]\naddress: \"10.99.0.1/24\"\nlisten_port: {port}\nclients: []\n"
        )
    }

    fn ruleset(meta: &str, table: &str) -> String {
        format!("slipmesh:\n  kind: nftables\n{meta}ruleset: |\n  table inet {table} {{}}\n")
    }

    fn error(raw: &str) -> String {
        match SlipmeshFile::parse(raw) {
            Ok(_) => panic!("parsed, but should have been refused:\n{raw}"),
            Err(err) => format!("{err:#}"),
        }
    }

    // The file as a whole.

    #[test]
    fn hosts_come_from_the_network_document_in_its_order() {
        let parsed = SlipmeshFile::parse(NETWORK).unwrap();
        assert_eq!(parsed.hosts(), ["node-a", "node-b", "node-c"]);
    }

    #[test]
    fn a_file_without_a_network_document_is_refused() {
        assert!(error(KUBELET).contains("network"));
    }

    #[test]
    fn a_file_with_two_network_documents_is_refused() {
        assert!(error(&file(&[NETWORK, NETWORK])).contains("network"));
    }

    #[test]
    fn a_document_without_a_slipmesh_block_is_refused_by_its_line() {
        let raw = file(&[NETWORK, "stray: 1\n"]);
        let line = raw[..raw.find("---\nstray").unwrap()].matches('\n').count() + 1;
        let err = error(&raw);
        assert!(err.contains(&format!("line {line}")), "{err}");
        assert!(err.contains("slipmesh"), "{err}");
    }

    #[test]
    fn a_document_of_only_comments_is_not_one() {
        SlipmeshFile::parse(&file(&[NETWORK, "# end of file\n"])).unwrap();
    }

    #[test]
    fn an_unknown_kind_is_refused_with_the_known_ones() {
        let err = error(&file(&[NETWORK, "slipmesh:\n  kind: patches\na: 1\n"]));
        assert!(err.contains("patches"), "{err}");
        assert!(err.contains("roadwarriors"), "{err}");
    }

    #[test]
    fn a_misspelled_meta_key_is_refused() {
        let err = error(&file(&[
            NETWORK,
            "slipmesh:\n  kind: patch\n  tagrets: [node-a]\napiVersion: v1alpha1\nkind: KubeletConfig\n",
        ]));
        assert!(err.contains("tagrets"), "{err}");
    }

    #[test]
    fn an_empty_include_is_refused() {
        let err = error(&file(&[
            NETWORK,
            "slipmesh:\n  kind: patch\n  include: []\napiVersion: v1alpha1\nkind: KubeletConfig\n",
        ]));
        assert!(err.contains("include"), "{err}");
    }

    #[test]
    fn include_on_a_network_document_is_refused() {
        let network = NETWORK.replace(
            "  kind: network\n",
            "  kind: network\n  include: [node-a]\n",
        );
        let err = error(&network);
        assert!(err.contains("include"), "{err}");
    }

    #[test]
    fn exclude_on_a_roadwarriors_document_is_refused() {
        let pool = pool("plain", 51820).replace(
            "  kind: roadwarriors\n",
            "  kind: roadwarriors\n  exclude: [node-b]\n",
        );
        let err = error(&file(&[NETWORK, &pool]));
        assert!(err.contains("exclude"), "{err}");
    }

    #[test]
    fn an_unknown_host_in_include_or_exclude_is_refused_by_name() {
        for meta in ["  include: [node-z]\n", "  exclude: [node-z]\n"] {
            let err = error(&file(&[NETWORK, &ruleset(meta, "t")]));
            assert!(err.contains("node-z"), "{err}");
        }
    }

    #[test]
    fn an_unknown_field_is_refused_at_the_line_it_is_written_on() {
        let network = NETWORK.replace(
            "  bgp_as: 64512\n",
            "  bgp_as: 64512\n  metrics_port: 9586\n",
        );
        let raw = file(&[KUBELET, &network]);
        let line = raw[..raw.find("  metrics_port").unwrap()]
            .matches('\n')
            .count()
            + 1;
        let err = error(&raw);
        assert!(err.contains("cluster"), "{err}");
        assert!(err.contains("metrics_port"), "{err}");
        assert!(err.contains(&format!("line {line}")), "{err}");
    }

    #[test]
    fn a_network_document_with_its_meta_block_last_still_parses() {
        let network = format!(
            "{}slipmesh:\n  kind: network\n",
            NETWORK
                .strip_prefix("slipmesh:\n  kind: network\n")
                .unwrap()
        );
        SlipmeshFile::parse(&network).unwrap();
    }

    // What one host's patch file gets.

    #[test]
    fn a_patch_without_include_reaches_every_host() {
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, KUBELET])).unwrap();
        for host in ["node-a", "node-b", "node-c"] {
            assert_eq!(parsed.patches_for(host).unwrap().len(), 1, "{host}");
        }
    }

    #[test]
    fn a_patch_with_include_reaches_only_its_hosts() {
        let patch = KUBELET.replace("  kind: patch\n", "  kind: patch\n  include: [node-b]\n");
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, &patch])).unwrap();
        assert!(parsed.patches_for("node-a").unwrap().is_empty());
        assert_eq!(parsed.patches_for("node-b").unwrap().len(), 1);
    }

    #[test]
    fn a_host_in_exclude_does_not_get_the_patch() {
        let patch = KUBELET.replace("  kind: patch\n", "  kind: patch\n  exclude: [node-c]\n");
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, &patch])).unwrap();
        assert_eq!(parsed.patches_for("node-a").unwrap().len(), 1);
        assert!(parsed.patches_for("node-c").unwrap().is_empty());
    }

    #[test]
    fn a_single_source_patch_passes_through_byte_for_byte() {
        let patch = "slipmesh:\n  kind: patch\n  include: [node-a]\n# why this disk\napiVersion: v1alpha1\nkind: UnattendedInstallConfig   # trailing\ninstaller:\n    disk:   /dev/vda\n";
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, patch])).unwrap();
        let documents = parsed.patches_for("node-a").unwrap();
        assert_eq!(
            documents,
            [HostDocument {
                identity: "UnattendedInstallConfig".into(),
                text: "# why this disk\napiVersion: v1alpha1\nkind: UnattendedInstallConfig   # trailing\ninstaller:\n    disk:   /dev/vda".into(),
                sources: 1,
            }]
        );
    }

    #[test]
    fn a_block_scalar_with_a_trailing_space_and_a_pem_survives_verbatim() {
        let content = "      password: \"x\" \n      -----BEGIN CERTIFICATE-----\n      MIIB\n      -----END CERTIFICATE-----\n";
        let patch = format!(
            "slipmesh:\n  kind: patch\n  include: [node-b]\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: mikrotik\nconfigFiles:\n  - content: |\n{content}    mountPath: /etc/x\n"
        );
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, &patch])).unwrap();
        let documents = parsed.patches_for("node-b").unwrap();
        assert!(documents[0].text.contains(content), "{}", documents[0].text);
        assert_eq!(documents[0].identity, "ExtensionServiceConfig/mikrotik");
    }

    #[test]
    fn patches_of_one_identity_merge_with_the_included_one_over_the_default() {
        let host = "slipmesh:\n  kind: patch\n  include: [node-a]\napiVersion: v1alpha1\nkind: KubeletConfig\nextraArgs:\n    v: \"4\"\n";
        // The host document comes first in the file and still lands on top.
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, host, KUBELET])).unwrap();

        let merged = parsed.patches_for("node-a").unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].sources, 2);
        let value: yaml_serde::Value = yaml_serde::from_str(&merged[0].text).unwrap();
        assert_eq!(value["extraArgs"]["v"].as_str(), Some("4"));
        assert_eq!(
            value["extraArgs"]["rotate-server-certificates"].as_str(),
            Some("true")
        );

        assert_eq!(parsed.patches_for("node-b").unwrap()[0].sources, 1);
    }

    #[test]
    fn patches_come_out_in_the_order_their_identities_first_appear() {
        let install =
            "slipmesh:\n  kind: patch\napiVersion: v1alpha1\nkind: UnattendedInstallConfig\n";
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, install, KUBELET])).unwrap();
        let identities: Vec<_> = parsed
            .patches_for("node-a")
            .unwrap()
            .into_iter()
            .map(|d| d.identity)
            .collect();
        assert_eq!(identities, ["UnattendedInstallConfig", "KubeletConfig"]);
    }

    #[test]
    fn a_patch_without_kind_is_refused() {
        let err = error(&file(&[
            NETWORK,
            "slipmesh:\n  kind: patch\nmachine:\n  install: {disk: /dev/vda}\n",
        ]));
        assert!(err.contains("kind"), "{err}");
    }

    #[test]
    fn a_patch_claiming_a_generated_document_is_refused() {
        for name in ["awg", "router", "nftables"] {
            let err = error(&file(&[
                NETWORK,
                &format!(
                    "slipmesh:\n  kind: patch\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: {name}\n"
                ),
            ]));
            assert!(err.contains(name), "{err}");
        }
    }

    // The model each host is rendered from.

    #[test]
    fn pools_are_gathered_in_file_order() {
        let parsed = SlipmeshFile::parse(&file(&[
            NETWORK,
            &pool("second", 51821),
            &pool("first", 51820),
        ]))
        .unwrap();
        let names: Vec<_> = parsed
            .topology()
            .unwrap()
            .roadwarriors
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(names, ["second", "first"]);
    }

    #[test]
    fn a_pool_is_found_by_name_at_the_bytes_it_was_written_at() {
        let raw = file(&[NETWORK, &pool("first", 51820), &pool("second", 51821)]);
        let parsed = SlipmeshFile::parse(&raw).unwrap();
        let span = parsed.pool_span("second").unwrap();
        assert!(
            raw[span.clone()].contains("name: second"),
            "{}",
            &raw[span.clone()]
        );
        assert!(!raw[span.clone()].contains("name: first"));
        assert_eq!(span.end, raw.len());
        assert!(parsed.pool_span("third").is_none());
    }

    #[test]
    fn two_pools_of_one_name_are_refused() {
        let err = error(&file(&[
            NETWORK,
            &pool("plain", 51820),
            &pool("plain", 51821),
        ]));
        assert!(err.contains("plain"), "{err}");
    }

    #[test]
    fn pools_or_a_ruleset_inside_the_network_document_are_refused_by_their_kind() {
        for (section, kind) in [
            ("roadwarriors: []\n", "kind: roadwarriors"),
            ("nftables: {ruleset: x}\n", "kind: nftables"),
        ] {
            let err = error(&format!("{NETWORK}{section}"));
            assert!(err.contains(kind), "{err}");
        }
    }

    #[test]
    fn an_excluded_host_has_no_ruleset_rather_than_an_empty_one() {
        let parsed =
            SlipmeshFile::parse(&file(&[NETWORK, &ruleset("  exclude: [node-c]\n", "t")])).unwrap();
        assert!(parsed.effective_for("node-c").unwrap().nftables.is_none());
        let ruleset = parsed.effective_for("node-a").unwrap().nftables.unwrap();
        assert_eq!(ruleset.ruleset, "table inet t {}\n");
    }

    #[test]
    fn a_host_two_rulesets_reach_is_refused_by_name() {
        let err = error(&file(&[
            NETWORK,
            &ruleset("", "everyone"),
            &ruleset("  include: [node-b]\n", "extra"),
        ]));
        assert!(err.contains("node-b"), "{err}");
    }

    #[test]
    fn the_topology_carries_every_pool_and_no_ruleset() {
        let parsed = SlipmeshFile::parse(&file(&[
            NETWORK,
            &pool("plain", 51820),
            &ruleset("  include: [node-a]\n", "t"),
        ]))
        .unwrap();
        let topology = parsed.topology().unwrap();
        assert_eq!(topology.roadwarriors.len(), 1);
        assert!(topology.nftables.is_none());
    }
}
