//! Talos machine-config documents, as far as the generator reads and writes them.

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use sliplib_yaml::{Mapping, Value};
use std::collections::BTreeMap;

const API_VERSION: &str = "v1alpha1";
pub const EXTENSION_SERVICE_CONFIG: &str = "ExtensionServiceConfig";
pub const KUBE_NODE_CONFIG: &str = "KubeNodeConfig";

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
}

/// What Talos keys a document by: two documents of one identity are one document. Every other key
/// passes unread.
#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    #[serde(default, deserialize_with = "string")]
    pub api_version: Option<String>,
    #[serde(default, deserialize_with = "string")]
    pub kind: Option<String>,
    #[serde(default, deserialize_with = "string")]
    pub name: Option<String>,
}

/// A string as written: yaml_serde reads `5` or `true` as one when asked, Talos does not.
fn string<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    struct Written;
    impl serde::de::Visitor<'_> for Written {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string")
        }
        fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<String, E> {
            Ok(text.to_owned())
        }
    }
    struct Text(String);
    impl<'de> Deserialize<'de> for Text {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(Written).map(Text)
        }
    }
    Ok(Option::<Text>::deserialize(deserializer)?.map(|text| text.0))
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
    pub config_files: Vec<ServiceFile>,
}

/// A file of an `ExtensionServiceConfig`: one the generator writes, or one a patch adds, as written.
#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum ServiceFile {
    Generated(ConfigFile),
    Added(Value),
}

impl ExtensionServiceConfig {
    pub fn new(name: &str, config_files: Vec<ServiceFile>) -> Self {
        Self {
            api_version: API_VERSION.into(),
            kind: EXTENSION_SERVICE_CONFIG.into(),
            name: name.into(),
            config_files,
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConfigFile {
    pub mount_path: String,
    pub content: String,
}

/// An `ExtensionServiceConfig` the generator makes, as a patch may write it: files and nothing
/// else.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddedToGenerated {
    #[serde(rename = "apiVersion", default)]
    _api_version: IgnoredAny,
    #[serde(rename = "kind")]
    _kind: IgnoredAny,
    #[serde(rename = "name")]
    _name: IgnoredAny,
    #[serde(rename = "configFiles", default)]
    pub config_files: Option<Vec<AddedFile>>,
}

/// Of a file a patch adds, where it goes: every other key goes to Talos as written.
#[derive(Deserialize)]
pub struct AddedFile {
    #[serde(rename = "mountPath", default, deserialize_with = "string")]
    pub mount_path: Option<String>,
}

/// A `KubeNodeConfig`'s annotations, values unread: `null` is one too.
#[derive(Deserialize)]
pub struct Annotations {
    #[serde(default)]
    annotations: Option<BTreeMap<String, IgnoredAny>>,
}

impl Annotations {
    pub fn first_in(&self, namespace: &str) -> Option<&str> {
        self.annotations
            .iter()
            .flat_map(BTreeMap::keys)
            .map(String::as_str)
            .find(|key| key.starts_with(namespace))
    }
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
    document.get("kind").and_then(Value::as_str) == Some(KUBE_NODE_CONFIG)
}

/// Adds `annotations`, all in `namespace`, to the `KubeNodeConfig` `document`. Refuses one that
/// deletes the `KubeNodeConfig`, which would drop them.
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
    given
        .as_mapping_mut()
        .ok_or(Error::AnnotationsNotAMapping)?
        .extend(annotations);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sliplib_yaml::{from_str, to_value};

    fn identity(document: Value) -> Identity {
        sliplib_yaml::from_value(document).unwrap()
    }

    fn documents(text: &str) -> Vec<Value> {
        sliplib_yaml::MultiDoc::parse(text).unwrap().values()
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
            identity(documents[0].clone()),
            Identity {
                api_version: Some("v1alpha1".into()),
                kind: Some("ExtensionServiceConfig".into()),
                name: Some("awg".into()),
            }
        );
        let bare: Value = from_str("kind: HostnameConfig\n").unwrap();
        assert_eq!(identity(bare.clone()).api_version, None);
        assert_ne!(
            identity(documents[1].clone()),
            identity(documents[2].clone())
        );
    }

    #[test]
    fn an_identity_reads_as_its_kind_and_name() {
        let documents = documents(PATCH);
        assert_eq!(
            identity(documents[0].clone()).to_string(),
            "ExtensionServiceConfig/awg"
        );
        let unnamed: Value = from_str("kind: HostnameConfig\n").unwrap();
        assert_eq!(identity(unnamed.clone()).to_string(), "HostnameConfig");
    }

    #[test]
    fn an_extension_service_config_is_written_as_talos_reads_it() {
        let document = ExtensionServiceConfig::new(
            "awg",
            vec![ServiceFile::Generated(ConfigFile {
                mount_path: "/etc/node-a/awg.yaml".into(),
                content: "interfaces: []\n".into(),
            })],
        );
        let expected: Value = from_str(
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles:\n  - \
             mountPath: /etc/node-a/awg.yaml\n    content: \"interfaces: []\\n\"\n",
        )
        .unwrap();
        assert_eq!(to_value(&document).unwrap(), expected);
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
        let err = annotate(&mut document, NAMESPACE, ours()).unwrap_err();
        assert!(
            matches!(&err, Error::DeletesAnnotated { namespace } if namespace == NAMESPACE),
            "{err}"
        );
    }

    #[test]
    fn an_annotation_in_the_namespace_is_found_even_set_to_null() {
        let annotations = |text: &str| -> Annotations { from_str(text).unwrap() };
        let document = annotations(
            "kind: KubeNodeConfig\nannotations:\n  example.com/role: x\n  node-a.example/other: \
             null\n",
        );
        assert_eq!(document.first_in(NAMESPACE), Some("node-a.example/other"));
        let outside = annotations("kind: KubeNodeConfig\nannotations:\n  example.com/role: x\n");
        assert_eq!(outside.first_in(NAMESPACE), None);
        assert_eq!(
            annotations("kind: KubeNodeConfig\n").first_in(NAMESPACE),
            None
        );
    }

    #[test]
    fn annotations_that_are_not_a_mapping_take_none() {
        let mut document = yaml("kind: KubeNodeConfig\nannotations: [x]\n");
        let err = annotate(&mut document, NAMESPACE, ours()).unwrap_err();
        assert!(matches!(err, Error::AnnotationsNotAMapping), "{err}");
    }
}
