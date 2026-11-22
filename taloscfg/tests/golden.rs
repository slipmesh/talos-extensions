//! What every node of `talos` of the twins under `golden/` gets from `slipmesh-taloscfg
//! generate`. Each twin, `v2` and `v2-alternate`, is a network of format version 1 converted by
//! hand. `v1` and `v1-alternate` hold the patch files version 1 gave it, with derived public keys
//! named by their owner. Every node gets its file, but for what a conversion changes, applied to
//! the files here: no pool interface, no bypass list, no label on what is announced, the link's
//! port where a node's endpoint held another, the endpoint annotation without that port, and the
//! `nftables` document, which the generator makes from a `template` now, after `router` and not
//! among the `patch` documents. A change of what a node gets fails here, and changes what the
//! nodes of a working network are configured with.

use sliplib_config::awg::AwgConfig;
use sliplib_config::router::RouterConfig;
use sliplib_yaml::{MultiDoc, Value};
use std::path::Path;
use std::process::Command;
use taloscfg::patch_file::HEADER;

/// A network written in version 2, beside the patch files its file of version 1 gave.
struct Twin {
    /// The directory of the patch files of version 1.
    configs: &'static str,
    text: &'static str,
    /// The nodes of `talos`, in the order written. A node of another platform gets no patch file,
    /// though version 1 wrote one for every node.
    nodes: &'static [&'static str],
    /// An endpoint a peer dialed in version 1 because the node wrote a port into its own, and the
    /// one it dials now: the node's address and the link's port.
    redialed: &'static [(&'static str, &'static str)],
    /// The same endpoint in the node's annotation, and the address it carries now.
    annotated: &'static [(&'static str, &'static str)],
}

const FULL: Twin = Twin {
    configs: "v1",
    text: include_str!("golden/v2/slipmesh.yaml"),
    nodes: &["node-a", "node-b", "node-c", "node-d", "node-e", "node-f"],
    redialed: &[("192.0.2.4:51999", "192.0.2.4:51832")],
    annotated: &[("192.0.2.4:51999", "192.0.2.4")],
};

const ALTERNATE: Twin = Twin {
    configs: "v1-alternate",
    text: include_str!("golden/v2-alternate/slipmesh.yaml"),
    nodes: &["east", "west", "south"],
    redialed: &[],
    annotated: &[],
};

fn generate(config: &Path, patches: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_slipmesh-taloscfg"))
        .arg("generate")
        .arg("--config")
        .arg(config)
        .arg("--patches-dir")
        .arg(patches)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn documents(text: &str) -> Vec<Value> {
    MultiDoc::parse(text)
        .unwrap()
        .documents()
        .iter()
        .map(|document| document.value.clone())
        .collect()
}

/// `documents` as the text of a patch file.
fn patch_file(documents: &[Value]) -> String {
    let texts: Vec<String> = documents
        .iter()
        .map(|document| sliplib_yaml::to_string(document).unwrap())
        .collect();
    format!("{HEADER}{}", sliplib_yaml::join(&texts))
}

/// The position of the `ExtensionServiceConfig` named `name` among `documents`.
fn position(documents: &[Value], name: &str) -> Option<usize> {
    documents.iter().position(|document| {
        document["kind"] == "ExtensionServiceConfig" && document["name"] == name
    })
}

/// The text of the first file of the `ExtensionServiceConfig` named `name`, the daemon's config,
/// read as `T`, edited by `edit` and written back.
fn edit_config<T>(documents: &mut [Value], name: &str, edit: impl FnOnce(&mut T))
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let index = position(documents, name).unwrap();
    let content = &mut documents[index]["configFiles"][0]["content"];
    let mut config: T = sliplib_yaml::from_str(content.as_str().unwrap()).unwrap();
    edit(&mut config);
    *content = sliplib_yaml::to_string(&config).unwrap().into();
}

/// The patch file version 1 gave a node, `file`, as `twin` gives it after a conversion.
fn converted(twin: &Twin, file: &str) -> String {
    let mut documents = documents(file);
    edit_config(&mut documents, "awg", |awg: &mut AwgConfig| {
        awg.interfaces
            .retain(|interface| !interface.name.starts_with("rw-"));
        let endpoints = awg
            .interfaces
            .iter_mut()
            .flat_map(|interface| &mut interface.peers)
            .filter_map(|peer| peer.endpoint.as_mut());
        for endpoint in endpoints {
            if let Some((_, now)) = twin.redialed.iter().find(|(was, _)| endpoint == was) {
                *endpoint = (*now).to_owned();
            }
        }
    });
    edit_config(&mut documents, "router", |router: &mut RouterConfig| {
        router.bypass = None;
        for announced in &mut router.announce {
            announced.label = None;
        }
    });
    if let Some(nftables) = position(&documents, "nftables") {
        let nftables = documents.remove(nftables);
        let router = position(&documents, "router").unwrap();
        documents.insert(router + 1, nftables);
    }
    for document in documents
        .iter_mut()
        .filter(|d| d["kind"] == "KubeNodeConfig")
    {
        let Some(endpoint) = document["annotations"].get_mut("slipmesh.net/endpoint") else {
            continue;
        };
        if let Some((_, now)) = twin
            .annotated
            .iter()
            .find(|(was, _)| endpoint.as_str() == Some(was))
        {
            *endpoint = (*now).into();
        }
    }
    patch_file(&documents)
}

/// Every public key derived from a private key of the twin, with whose it is: the files name
/// them so.
fn derived_public_keys(text: &str) -> Vec<(String, String)> {
    let files = sliplib_config::v2::File::parse(text).unwrap();
    files
        .network()
        .nodes
        .iter()
        .filter_map(|(name, node)| {
            let key = node.wireguard.as_ref()?.private_key.as_ref()?;
            Some((key.public_key().unwrap(), format!("<public key of {name}>")))
        })
        .collect()
}

fn every_node_gets_what_version_1_gave_it_but_for_the_conversion(twin: &Twin) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("slipmesh.yaml");
    std::fs::write(&config, twin.text).unwrap();
    let patches = dir.path().join("patches");
    generate(&config, &patches);

    // Looked for by the names written here, not by what the generator made: a node it lost would
    // leave its file unread.
    let mut written: Vec<String> = std::fs::read_dir(&patches)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    written.sort();
    let mut expected: Vec<String> = twin
        .nodes
        .iter()
        .map(|node| format!("{node}.yaml"))
        .collect();
    expected.sort();
    assert_eq!(written, expected);

    let public_keys = derived_public_keys(twin.text);
    let golden = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(twin.configs);
    for host in twin.nodes {
        let path = golden.join(format!("{host}.yaml"));
        let file = std::fs::read_to_string(&path).unwrap();
        // Read and written back, the file is the text it holds: what the comparison below reads
        // of it is all it says.
        assert_eq!(patch_file(&documents(&file)), file, "{}", path.display());

        let got = std::fs::read_to_string(patches.join(format!("{host}.yaml"))).unwrap();
        let got = public_keys
            .iter()
            .fold(got, |text, (key, whose)| text.replace(key, whose));
        assert_eq!(
            patch_file(&documents(&got)),
            converted(twin, &file),
            "{host}"
        );
    }
}

#[test]
fn every_node_of_the_full_twin_gets_what_version_1_gave_it_but_for_the_conversion() {
    every_node_gets_what_version_1_gave_it_but_for_the_conversion(&FULL);
}

#[test]
fn every_node_of_the_alternate_twin_gets_what_version_1_gave_it_but_for_the_conversion() {
    every_node_gets_what_version_1_gave_it_but_for_the_conversion(&ALTERNATE);
}
