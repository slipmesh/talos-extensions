//! Talos machine-config documents, as far as the generator reads and writes them.

use serde::{Deserialize, Serialize};
use sliplib_yaml::{Mapping, Value};

const API_VERSION: &str = "v1alpha1";
const EXTENSION_SERVICE_CONFIG: &str = "ExtensionServiceConfig";
const KUBE_NODE_CONFIG: &str = "KubeNodeConfig";

/// The directive that turns a document into a deletion: a message to Talos, not values to merge.
const PATCH_KEY: &str = "$patch";

/// What is wrong with a Talos document these functions were given.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("serializing a file's contents")]
    Contents(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error(
        "a document deletes the {KUBE_NODE_CONFIG}, which carries the annotations in {namespace} - drop its `{PATCH_KEY}: delete`"
    )]
    DeletesAnnotated { namespace: String },
    #[error("a {KUBE_NODE_CONFIG} document is not a mapping")]
    NotAMapping,
    #[error("the annotations of a {KUBE_NODE_CONFIG} are not a mapping")]
    AnnotationsNotAMapping,
    #[error(
        "a document sets the annotation {set}, and those in {namespace} are generated - take it out of the document"
    )]
    SetsGenerated { set: String, namespace: String },
}

/// What Talos keys a document by: two documents of one identity are one document.
#[derive(Debug, PartialEq, Eq)]
pub struct Identity {
    pub api_version: Option<String>,
    pub kind: Option<String>,
    pub name: Option<String>,
}

impl Identity {
    pub fn of(document: &Value) -> Self {
        let field = |key: &str| document.get(key).and_then(Value::as_str).map(str::to_owned);
        Self {
            api_version: field("apiVersion"),
            kind: field("kind"),
            name: field("name"),
        }
    }

    fn is_extension_service(&self, name: &str) -> bool {
        self.kind.as_deref() == Some(EXTENSION_SERVICE_CONFIG) && self.name.as_deref() == Some(name)
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

/// The files Talos mounts into the extension service `name`.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionServiceConfig {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub config_files: Vec<ConfigFile>,
}

impl ExtensionServiceConfig {
    pub fn new(name: &str, config_files: Vec<ConfigFile>) -> Self {
        Self {
            api_version: API_VERSION.into(),
            kind: EXTENSION_SERVICE_CONFIG.into(),
            name: name.into(),
            config_files,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConfigFile {
    pub mount_path: String,
    pub content: String,
}

/// Whether `document` is the `ExtensionServiceConfig` of `service` and sets its file `mount_path`.
pub fn sets_file(document: &Value, service: &str, mount_path: &str) -> bool {
    Identity::of(document).is_extension_service(service)
        && document
            .get("configFiles")
            .and_then(Value::as_sequence)
            .into_iter()
            .flatten()
            .any(|f| f.get("mountPath").and_then(Value::as_str) == Some(mount_path))
}

/// Replaces each `configFiles[].content` of `document` written as a mapping or a list with that
/// YAML's text: Talos takes only a string there.
pub fn contents_as_text(document: &mut Value) -> Result<(), Error> {
    let Some(files) = document
        .get_mut("configFiles")
        .and_then(Value::as_sequence_mut)
    else {
        return Ok(());
    };
    for content in files.iter_mut().filter_map(|file| file.get_mut("content")) {
        if content.is_mapping() || content.is_sequence() {
            let text = sliplib_yaml::to_string(&*content)
                .map_err(|source| Error::Contents(source.into()))?;
            *content = Value::String(text);
        }
    }
    Ok(())
}

/// `overlay` merged over `base`, two documents of one identity: JSON Merge Patch, as
/// [`sliplib_yaml::merge`] does it. A `$patch: delete` document on either side is not merged - over
/// the base it would turn a deletion into an edit, under the overlay an edit into a deletion - and
/// the overlay replaces the result outright.
///
/// Sequences are replaced rather than appended, unlike Talos' own strategic merge: Talos appends to
/// a keyed list by its key because it knows the types, and schemaless YAML could neither remove an
/// element nor tell that two `configFiles` entries share a `mountPath`.
pub fn merge(base: Value, overlay: &Value) -> Value {
    if is_deletion(overlay) || is_deletion(&base) {
        return overlay.clone();
    }
    sliplib_yaml::merge(base, overlay)
}

fn is_deletion(document: &Value) -> bool {
    document.get(PATCH_KEY).and_then(Value::as_str) == Some("delete")
}

/// A `KubeNodeConfig` that sets nothing: the document of the node's labels, annotations and
/// taints, one to a machine config.
pub fn kube_node_config() -> Value {
    Value::Mapping(Mapping::from_iter([
        ("apiVersion".into(), API_VERSION.into()),
        ("kind".into(), KUBE_NODE_CONFIG.into()),
    ]))
}

pub fn is_kube_node_config(document: &Value) -> bool {
    Identity::of(document).kind.as_deref() == Some(KUBE_NODE_CONFIG)
}

/// Adds `annotations`, all in `namespace`, to the `KubeNodeConfig` `document`. Refuses a document
/// that sets an annotation in `namespace` itself, which `annotations` would overwrite silently, and
/// one that deletes the `KubeNodeConfig`, which would drop them.
pub fn annotate(document: &mut Value, namespace: &str, annotations: Mapping) -> Result<(), Error> {
    if is_deletion(document) {
        return Err(Error::DeletesAnnotated {
            namespace: namespace.to_owned(),
        });
    }
    let given = document
        .as_mapping_mut()
        .ok_or(Error::NotAMapping)?
        .entry("annotations".into())
        .or_insert(Value::Null);
    if given.is_null() {
        *given = Value::Mapping(Mapping::new());
    }
    let given = given
        .as_mapping_mut()
        .ok_or(Error::AnnotationsNotAMapping)?;
    if let Some(set) = given
        .keys()
        .filter_map(Value::as_str)
        .find(|key| key.starts_with(namespace))
    {
        return Err(Error::SetsGenerated {
            set: set.to_owned(),
            namespace: namespace.to_owned(),
        });
    }
    given.extend(annotations);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sliplib_yaml::{from_str, to_value};

    fn documents(text: &str) -> Vec<Value> {
        sliplib_yaml::MultiDoc::parse(text)
            .unwrap()
            .documents()
            .iter()
            .map(|d| d.value.clone())
            .collect()
    }

    const PATCH: &str = "\
apiVersion: v1alpha1
kind: ExtensionServiceConfig
name: awg
configFiles:
  - mountPath: /etc/node-a/awg.yaml
    content: |
      interfaces: []
  - mountPath: /etc/node-a/extra.conf
    content: extra
---
apiVersion: v1alpha1
kind: OtherConfig
name: router
---
apiVersion: v1alpha1
kind: ExtensionServiceConfig
name: router
configFiles:
  - mountPath: /etc/node-a/router.yaml
    content: |
      bgp_as: 64512
";

    #[test]
    fn a_documents_identity_is_its_api_version_kind_and_name() {
        let documents = documents(PATCH);
        assert_eq!(
            Identity::of(&documents[0]),
            Identity {
                api_version: Some("v1alpha1".into()),
                kind: Some("ExtensionServiceConfig".into()),
                name: Some("awg".into()),
            }
        );
        let bare: Value = from_str("kind: HostnameConfig\n").unwrap();
        assert_eq!(Identity::of(&bare).api_version, None);
        assert_ne!(Identity::of(&documents[1]), Identity::of(&documents[2]));
    }

    #[test]
    fn an_identity_reads_as_its_kind_and_name() {
        let documents = documents(PATCH);
        assert_eq!(
            Identity::of(&documents[0]).to_string(),
            "ExtensionServiceConfig/awg"
        );
        let unnamed = from_str("kind: HostnameConfig\n").unwrap();
        assert_eq!(Identity::of(&unnamed).to_string(), "HostnameConfig");
    }

    #[test]
    fn an_extension_service_config_is_written_as_talos_reads_it() {
        let document = ExtensionServiceConfig::new(
            "awg",
            vec![ConfigFile {
                mount_path: "/etc/node-a/awg.yaml".into(),
                content: "interfaces: []\n".into(),
            }],
        );
        let expected: Value = from_str(
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles:\n  - \
             mountPath: /etc/node-a/awg.yaml\n    content: \"interfaces: []\\n\"\n",
        )
        .unwrap();
        assert_eq!(to_value(&document).unwrap(), expected);
    }

    #[test]
    fn a_document_sets_a_file_of_its_own_service_only() {
        let documents = documents(PATCH);
        assert!(sets_file(&documents[0], "awg", "/etc/node-a/extra.conf"));
        assert!(!sets_file(&documents[0], "awg", "/etc/node-a/router.yaml"));
        assert!(!sets_file(
            &documents[0],
            "router",
            "/etc/node-a/extra.conf"
        ));
        assert!(!sets_file(
            &documents[1],
            "router",
            "/etc/node-a/router.yaml"
        ));
    }

    #[test]
    fn a_content_written_as_yaml_becomes_its_text() {
        let mut document: Value = from_str(
            "kind: ExtensionServiceConfig\nconfigFiles:\n  - content:\n      a: 1\n  \
             - content:\n      - b\n  - content: plain\n",
        )
        .unwrap();
        contents_as_text(&mut document).unwrap();
        let contents: Vec<&str> = document["configFiles"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|file| file["content"].as_str().unwrap())
            .collect();
        assert_eq!(contents, ["a: 1\n", "- b\n", "plain"]);
        let mut no_files: Value = from_str("kind: HostnameConfig\n").unwrap();
        contents_as_text(&mut no_files).unwrap();
        assert_eq!(
            no_files,
            from_str::<Value>("kind: HostnameConfig\n").unwrap()
        );
    }

    fn yaml(text: &str) -> Value {
        from_str(text).unwrap()
    }

    #[test]
    fn a_delete_directive_on_the_overlay_replaces_the_result() {
        let overlay = yaml("apiVersion: v1alpha1\nkind: KubeletConfig\n$patch: delete");
        let merged = merge(
            yaml("apiVersion: v1alpha1\nkind: KubeletConfig\nextraArgs: {a: b}"),
            &overlay,
        );
        assert_eq!(merged, overlay);
    }

    #[test]
    fn a_document_over_a_delete_directive_replaces_it() {
        let overlay = yaml("apiVersion: v1alpha1\nkind: KubeletConfig\nextraArgs: {a: b}");
        let merged = merge(
            yaml("apiVersion: v1alpha1\nkind: KubeletConfig\n$patch: delete"),
            &overlay,
        );
        assert_eq!(merged, overlay);
    }

    #[test]
    fn a_nested_patch_key_is_an_ordinary_key() {
        let merged = merge(
            yaml("machine: {install: {disk: /dev/vda}}"),
            &yaml("machine: {install: {$patch: delete}}"),
        );
        assert_eq!(
            merged,
            yaml("machine: {install: {disk: /dev/vda, $patch: delete}}")
        );
    }

    #[test]
    fn a_new_kube_node_config_is_known_by_its_kind() {
        let document = kube_node_config();
        assert_eq!(
            document,
            yaml("apiVersion: v1alpha1\nkind: KubeNodeConfig\n")
        );
        assert!(is_kube_node_config(&document));
        assert!(!is_kube_node_config(&documents(PATCH)[0]));
    }

    const NAMESPACE: &str = "node-a.example/";

    fn ours() -> Mapping {
        Mapping::from_iter([("node-a.example/endpoint".into(), "192.0.2.10".into())])
    }

    #[test]
    fn annotations_join_those_the_document_sets() {
        let mut document = yaml(
            "kind: KubeNodeConfig\nnodeIP: {validSubnets: [192.0.2.0/24]}\nannotations:\n  \
             example.com/rack: r1\n",
        );
        annotate(&mut document, NAMESPACE, ours()).unwrap();
        assert_eq!(
            document,
            yaml(
                "kind: KubeNodeConfig\nnodeIP: {validSubnets: [192.0.2.0/24]}\nannotations:\n  \
                 example.com/rack: r1\n  node-a.example/endpoint: 192.0.2.10\n"
            )
        );
    }

    #[test]
    fn annotations_go_into_a_document_that_sets_none() {
        for text in [
            "kind: KubeNodeConfig\n",
            "kind: KubeNodeConfig\nannotations:\n",
        ] {
            let mut document = yaml(text);
            annotate(&mut document, NAMESPACE, ours()).unwrap();
            assert_eq!(document["annotations"], Value::Mapping(ours()), "{text}");
        }
    }

    #[test]
    fn a_document_that_deletes_itself_takes_no_annotations() {
        let mut document = yaml("kind: KubeNodeConfig\n$patch: delete\n");
        let err = format!(
            "{:#}",
            annotate(&mut document, NAMESPACE, ours()).unwrap_err()
        );
        assert!(err.contains("KubeNodeConfig"), "{err}");
    }

    #[test]
    fn a_document_that_sets_an_annotation_in_the_namespace_takes_none() {
        let mut document = yaml("kind: KubeNodeConfig\nannotations:\n  node-a.example/other: x\n");
        let err = format!(
            "{:#}",
            annotate(&mut document, NAMESPACE, ours()).unwrap_err()
        );
        assert!(err.contains("node-a.example/other"), "{err}");
    }
}
