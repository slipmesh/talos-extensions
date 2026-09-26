//! `slipmesh.yaml`: what each document in it is, which hosts it reaches, and what one host ends up
//! with.
//!
//! Every document carries a `slipmesh:` block saying what it is for. `network` is the topology,
//! exactly one of it. `roadwarriors` is one pool per document. `nftables` is a ruleset, and
//! `patch` is a Talos document, both aimed at hosts by `include`/`exclude`. The block is addressed
//! to this tool and never reaches a patch file.

use crate::merge::merge_document;
use crate::mesh_config::{self, MeshConfig, NftablesTopology, RoadwarriorPool};
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::ops::Range;
use yaml_rt::{NodeId, YamlDoc};
use yaml_serde::Value;

/// The generator's own top-level block in every document: what the document is for and which
/// hosts it reaches.
pub const META_KEY: &str = "slipmesh";

/// The `ExtensionServiceConfig` names this tool generates itself, and so refuses in a `patch`
/// document. Talos keeps `name` unique per `kind`, so the pair is the whole identity.
pub const OWNED_NAMES: [&str; 3] = ["awg", "router", "nftables"];

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
    /// Its position among the documents of the file, those of only comments included - how
    /// `yaml-rt` addresses it.
    index: usize,
    line: usize,
    meta: Meta,
    /// The document parsed, without the `slipmesh:` block.
    value: Value,
    /// The document's text with the `slipmesh:` block blanked out, behind as many empty lines as
    /// come before it in the file - deserialized from this, a document's error names the line of
    /// the file it is on.
    positioned: String,
}

impl Document {
    /// The document at `index`, whose text is `raw[span]`. `None` for a document with nothing in
    /// it but comments: it says nothing to route.
    fn read(raw: &str, yaml: &YamlDoc, index: usize, span: Range<usize>) -> Result<Option<Self>> {
        let Some(root) = yaml.document_root(index)? else {
            return Ok(None);
        };
        let line = raw[..span.start].matches('\n').count() + 1;
        let text = &raw[span.clone()];
        let read = || -> Result<Self> {
            let mut value: Value = yaml_serde::from_str(text).context("not valid YAML")?;
            let meta = value
                .as_mapping_mut()
                .and_then(|mapping| mapping.shift_remove(META_KEY))
                .context("no `slipmesh:` block saying what the document is for")?;
            let meta: Meta = yaml_serde::from_value(meta).context("its `slipmesh:` block")?;
            let mut blanked = text.to_owned();
            if let Some(entry) = yaml.get_mapping_entry(root, META_KEY)? {
                let entry = span_of(yaml, entry)?;
                let entry = entry.start - span.start..entry.end - span.start;
                let lines = "\n".repeat(blanked[entry.clone()].matches('\n').count());
                blanked.replace_range(entry, &lines);
            }
            Ok(Self {
                index,
                line,
                meta,
                value,
                positioned: "\n".repeat(line - 1) + &blanked,
            })
        };
        read()
            .map(Some)
            .with_context(|| format!("the document starting at line {line}"))
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

/// The byte range of `node` in the source.
fn span_of(yaml: &YamlDoc, node: NodeId) -> Result<Range<usize>> {
    let span = yaml
        .node(node)
        .context("a node the parser did not keep")?
        .span();
    Ok(span.start as usize..span.end as usize)
}

/// One Talos document as it goes into one host's patch file, serialized - its comments stay in
/// `slipmesh.yaml`.
#[derive(Debug, PartialEq)]
pub struct HostDocument {
    /// `kind`, plus `/name` when the document has one.
    pub identity: String,
    pub text: String,
}

pub struct SlipmeshFile {
    network: Value,
    network_index: usize,
    hosts: Vec<String>,
    pools: Vec<Document>,
    rulesets: Vec<Document>,
    patches: Vec<Document>,
    topology: MeshConfig,
}

impl SlipmeshFile {
    pub fn parse(raw: &str) -> Result<Self> {
        Self::read(raw, &YamlDoc::parse(raw)?)
    }

    /// `yaml` parsed from `raw` - for a caller that goes on to edit it.
    pub fn read(raw: &str, yaml: &YamlDoc) -> Result<Self> {
        let mut networks = Vec::new();
        let mut pools = Vec::new();
        let mut rulesets = Vec::new();
        let mut patches = Vec::new();
        // Each document runs to where the next one starts. Its own span cannot say where it ends:
        // `yaml-rt` ends the span of a block scalar at its `|`, before the text under it.
        let mut starts: Vec<usize> = yaml
            .documents()
            .map(|document| span_of(yaml, document).map(|span| span.start))
            .collect::<Result<_>>()?;
        if let Some(first) = starts.first_mut() {
            *first = 0;
        }
        for (index, &start) in starts.iter().enumerate() {
            let end = starts.get(index + 1).copied().unwrap_or(raw.len());
            let Some(document) = Document::read(raw, yaml, index, start..end)? else {
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
                    "{}: has no Talos `kind`, so it has no identity to merge by",
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

        let topology = model(&network.value, &pools, None)?;
        Ok(Self {
            network_index: network.index,
            network: network.value,
            hosts,
            pools,
            rulesets,
            patches,
            topology,
        })
    }

    /// The position of the `network` document in the file - where an edit to the topology goes.
    pub fn network_document(&self) -> usize {
        self.network_index
    }

    /// The position of the `roadwarriors` document holding pool `name` - where an edit to that
    /// pool goes.
    pub fn pool_document(&self, name: &str) -> Option<usize> {
        self.pools
            .iter()
            .find(|p| p.value.get("name").and_then(Value::as_str) == Some(name))
            .map(|p| p.index)
    }

    /// The hosts `network` names, in its order.
    pub fn hosts(&self) -> Vec<&str> {
        self.hosts.iter().map(String::as_str).collect()
    }

    /// The whole topology: `network` with every pool, and no ruleset - the ruleset differs by host
    /// and plays no part in anything shared between them, such as secrets.
    pub fn topology(&self) -> &MeshConfig {
        &self.topology
    }

    pub fn into_topology(self) -> MeshConfig {
        self.topology
    }

    /// The topology as one host sees it: with the ruleset aimed at that host, if any.
    pub fn effective_for(&self, host: &str) -> Result<MeshConfig> {
        self.ensure_host(host)?;
        let ruleset = self.rulesets.iter().find(|r| r.reaches(host));
        model(&self.network, &self.pools, ruleset.map(|r| r.value.clone()))
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
                let [first, rest @ ..] = sources.as_slice() else {
                    unreachable!("every identity comes from at least one document")
                };
                let mut document = rest.iter().fold(first.value.clone(), |base, patch| {
                    merge_document(base, &patch.value)
                });
                contents_as_text(&mut document)?;
                let serialized =
                    yaml_serde::to_string(&document).context("serializing a patch document")?;
                // One line break, the one the serializer ends with: any more belong to a `|+`
                // block scalar's value.
                let text = serialized
                    .strip_suffix('\n')
                    .unwrap_or(&serialized)
                    .to_owned();
                Ok(HostDocument {
                    identity: identity.to_string(),
                    text,
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
}

/// `network` with every pool and `ruleset`, as one validated model.
fn model(network: &Value, pools: &[Document], ruleset: Option<Value>) -> Result<MeshConfig> {
    let mut value = network.clone();
    let mapping = value
        .as_mapping_mut()
        .context("the network document is not a mapping")?;
    let pools = pools.iter().map(|p| p.value.clone()).collect();
    mapping.insert("roadwarriors".into(), Value::Sequence(pools));
    if let Some(ruleset) = ruleset {
        mapping.insert("nftables".into(), ruleset);
    }
    let model: MeshConfig = yaml_serde::from_value(value).context("assembling the topology")?;
    mesh_config::validate(&model)?;
    Ok(model)
}

/// Replaces each `configFiles[].content` of `document` written as a mapping or a list with that
/// YAML's text.
///
/// Such a content is the file's contents given as YAML, each of its fields a field of
/// `slipmesh.yaml` like any other. Talos takes only a string there.
fn contents_as_text(document: &mut Value) -> Result<()> {
    let Some(files) = document
        .get_mut("configFiles")
        .and_then(Value::as_sequence_mut)
    else {
        return Ok(());
    };
    for content in files.iter_mut().filter_map(|file| file.get_mut("content")) {
        if content.is_mapping() || content.is_sequence() {
            let text = yaml_serde::to_string(&*content).context("serializing a file's contents")?;
            *content = Value::String(text);
        }
    }
    Ok(())
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
    fn a_patch_goes_out_as_the_serializer_writes_it_without_its_slipmesh_block() {
        let patch = "slipmesh:\n  kind: patch\n  include: [node-a]\n# why this disk\napiVersion: v1alpha1\nkind: UnattendedInstallConfig   # trailing\ninstaller:\n    disk:   /dev/vda\n";
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, patch])).unwrap();
        let documents = parsed.patches_for("node-a").unwrap();
        assert_eq!(
            documents,
            [HostDocument {
                identity: "UnattendedInstallConfig".into(),
                text: "apiVersion: v1alpha1\nkind: UnattendedInstallConfig\ninstaller:\n  disk: /dev/vda"
                    .into(),
            }]
        );
    }

    #[test]
    fn a_block_scalar_with_a_trailing_space_and_a_pem_keeps_its_value() {
        let block = "      password: \"x\" \n      -----BEGIN CERTIFICATE-----\n      MIIB\n      -----END CERTIFICATE-----\n";
        let patch = format!(
            "slipmesh:\n  kind: patch\n  include: [node-b]\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: mikrotik\nconfigFiles:\n  - content: |\n{block}    mountPath: /etc/x\n"
        );
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, &patch])).unwrap();
        let documents = parsed.patches_for("node-b").unwrap();
        assert_eq!(
            content(&documents[0].text, 0).as_str(),
            Some(
                "password: \"x\" \n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
            ),
            "{}",
            documents[0].text
        );
        assert_eq!(documents[0].identity, "ExtensionServiceConfig/mikrotik");
    }

    const DEVICE: &str = "slipmesh:\n  kind: patch\n  include: [node-b]\n# the device the converger talks to\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: device\nconfigFiles:\n  - mountPath: /etc/device.yaml\n    content:\n      host: router1.example.com\n      port: 8729\n      username: admin\n      password: hunter2   # the one secret here\n";

    /// A `configFiles[].content` in `text`, parsed as it lands in a patch file: followed by a line
    /// break, which a block scalar ending the document keeps.
    fn content(text: &str, index: usize) -> yaml_serde::Value {
        let value: yaml_serde::Value = yaml_serde::from_str(&format!("{text}\n")).unwrap();
        value["configFiles"][index]["content"].clone()
    }

    #[test]
    fn a_content_mapping_goes_out_as_the_text_of_that_yaml() {
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, DEVICE])).unwrap();
        let text = &parsed.patches_for("node-b").unwrap()[0].text;
        assert_eq!(
            content(text, 0).as_str(),
            Some("host: router1.example.com\nport: 8729\nusername: admin\npassword: hunter2\n"),
            "{text}"
        );
    }

    #[test]
    fn a_document_with_content_written_as_yaml_goes_out_as_the_serializer_writes_it() {
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, DEVICE])).unwrap();
        let text = &parsed.patches_for("node-b").unwrap()[0].text;
        assert_eq!(
            text,
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: device\nconfigFiles:\n- mountPath: /etc/device.yaml\n  content: |\n    host: router1.example.com\n    port: 8729\n    username: admin\n    password: hunter2"
        );
    }

    #[test]
    fn a_content_ending_in_blank_lines_keeps_them() {
        let patch = "slipmesh:\n  kind: patch\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: script\nconfigFiles:\n  - mountPath: /etc/script\n    content: \"run\\n\\n\\n\"\n";
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, patch])).unwrap();
        let text = &parsed.patches_for("node-a").unwrap()[0].text;
        assert_eq!(content(text, 0).as_str(), Some("run\n\n\n"), "{text}");
    }

    #[test]
    fn a_content_mapping_goes_out_as_text_after_a_merge_too() {
        let default = "slipmesh:\n  kind: patch\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: device\nconfigFiles:\n  - mountPath: /etc/device.yaml\n    content:\n      host: router0.example.com\n";
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, default, DEVICE])).unwrap();
        let documents = parsed.patches_for("node-b").unwrap();
        assert_eq!(
            content(&documents[0].text, 0).as_str(),
            Some("host: router1.example.com\nport: 8729\nusername: admin\npassword: hunter2\n")
        );
        assert_eq!(
            content(&parsed.patches_for("node-a").unwrap()[0].text, 0).as_str(),
            Some("host: router0.example.com\n")
        );
    }

    #[test]
    fn patches_of_one_identity_merge_with_the_included_one_over_the_default() {
        let host = "slipmesh:\n  kind: patch\n  include: [node-a]\napiVersion: v1alpha1\nkind: KubeletConfig\nextraArgs:\n    v: \"4\"\n";
        // The host document comes first in the file and still lands on top.
        let parsed = SlipmeshFile::parse(&file(&[NETWORK, host, KUBELET])).unwrap();

        let merged = parsed.patches_for("node-a").unwrap();
        assert_eq!(merged.len(), 1);
        let value: yaml_serde::Value = yaml_serde::from_str(&merged[0].text).unwrap();
        assert_eq!(value["extraArgs"]["v"].as_str(), Some("4"));
        assert_eq!(
            value["extraArgs"]["rotate-server-certificates"].as_str(),
            Some("true")
        );
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
            .roadwarriors
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(names, ["second", "first"]);
    }

    #[test]
    fn documents_are_found_by_their_position_in_the_file() {
        // A document of only comments holds a position too.
        let raw = file(&[
            NETWORK,
            &pool("first", 51820),
            "# nothing here yet\n",
            &pool("second", 51821),
        ]);
        let parsed = SlipmeshFile::parse(&raw).unwrap();
        assert_eq!(parsed.network_document(), 0);
        assert_eq!(parsed.pool_document("first"), Some(1));
        assert_eq!(parsed.pool_document("second"), Some(3));
        assert_eq!(parsed.pool_document("third"), None);
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
        let topology = parsed.topology();
        assert_eq!(topology.roadwarriors.len(), 1);
        assert!(topology.nftables.is_none());
    }
}
