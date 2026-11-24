//! Talos machine-config documents, as far as the generator reads and writes them.

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use sliplib_yaml::{Mapping, Value};
use std::collections::BTreeMap;

const API_VERSION: &str = "v1alpha1";
pub const EXTENSION_SERVICE_CONFIG: &str = "ExtensionServiceConfig";
pub const KUBE_NODE_CONFIG: &str = "KubeNodeConfig";

/// What is wrong with a Talos document these functions were given.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("serializing a file's contents")]
    Contents(#[source] Box<dyn std::error::Error + Send + Sync>),
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
    #[serde(rename = "configFiles")]
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

/// A `KubeNodeConfig` that sets nothing: the document of the node's labels, annotations and
/// taints, one to a machine config.
pub fn kube_node_config() -> Value {
    Value::Mapping(Mapping::from_iter([
        ("apiVersion".into(), API_VERSION.into()),
        ("kind".into(), KUBE_NODE_CONFIG.into()),
    ]))
}

/// The `KubeNodeConfig` `document` with `annotations` merged over its own.
pub fn annotate(document: Value, annotations: Mapping) -> Value {
    let patch = Mapping::from_iter([("annotations".into(), Value::Mapping(annotations))]);
    sliplib_yaml::merge(document, &Value::Mapping(patch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sliplib_yaml::{from_str, to_value};

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
    fn a_new_kube_node_config_sets_nothing() {
        assert_eq!(
            kube_node_config(),
            yaml("apiVersion: v1alpha1\nkind: KubeNodeConfig\n")
        );
    }
}
