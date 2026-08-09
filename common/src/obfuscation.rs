//! AmneziaWG's device-level obfuscation parameters. Ported from `slipmesh-core`'s
//! `mesh_types::Obfuscation` (github.com/slipmesh/core) - same nine fields, minus the
//! `schemars`/Kubernetes-CRD-schema annotations that crate carries them with, since nothing here
//! ever renders an OpenAPI schema.

use serde::Deserialize;

#[derive(Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Obfuscation {
    #[serde(default)]
    pub jc: Option<u16>,
    #[serde(default)]
    pub jmin: Option<u16>,
    #[serde(default)]
    pub jmax: Option<u16>,
    #[serde(default)]
    pub s1: Option<u16>,
    #[serde(default)]
    pub s2: Option<u16>,
    #[serde(default)]
    pub h1: Option<u32>,
    #[serde(default)]
    pub h2: Option<u32>,
    #[serde(default)]
    pub h3: Option<u32>,
    #[serde(default)]
    pub h4: Option<u32>,
}
