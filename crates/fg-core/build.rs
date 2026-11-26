#![forbid(unsafe_code)]

use std::{collections::BTreeSet, env, fs, io::Write, path::PathBuf};

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    module: Vec<Module>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Module {
    id: String,
    group: String,
    core: bool,
    requires: Vec<String>,
    tag: Option<String>,
    size_kb: Option<u32>,
    title: Localized,
    description: Localized,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Localized {
    zh_cn: String,
    zh_tw: String,
    en: String,
}

impl Localized {
    fn rust(&self) -> String {
        format!(
            "Localized {{ zh_cn: {:?}, zh_tw: {:?}, en: {:?} }}",
            self.zh_cn, self.zh_tw, self.en
        )
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const MANIFEST: &str = "../../features.toml";
    println!("cargo:rerun-if-changed={MANIFEST}");
    let manifest: Manifest = toml::from_str(&fs::read_to_string(MANIFEST)?)?;
    let ids: BTreeSet<_> = manifest
        .module
        .iter()
        .map(|module| module.id.as_str())
        .collect();
    assert_eq!(ids.len(), manifest.module.len(), "duplicate module ID");

    let dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let mut output = fs::File::create(dir.join("catalog.rs"))?;
    writeln!(output, "pub const CATALOG: &[ModuleInfo] = &[")?;
    for module in manifest.module.iter() {
        assert!(
            module
                .requires
                .iter()
                .all(|id| id != &module.id && ids.contains(id.as_str())),
            "invalid dependencies for {}",
            module.id
        );
        writeln!(
            output,
            "ModuleInfo {{ id: {:?}, group: {:?}, core: {}, requires: &{:?}, tag: {:?}, size_kb: {:?}, title: {}, description: {} }},",
            module.id,
            module.group,
            module.core,
            module.requires,
            module.tag,
            module.size_kb,
            module.title.rust(),
            module.description.rust()
        )?;
    }
    writeln!(output, "];")?;
    Ok(())
}
