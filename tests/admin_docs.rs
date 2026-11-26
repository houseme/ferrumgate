use std::process::Command;

use anyhow::Result;

#[test]
fn api_docs_exports_the_actual_management_catalog() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_fgate"))
        .arg("api-docs")
        .arg(directory.path())
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let spec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.path().join("openapi.json"))?)?;
    assert_eq!(spec["openapi"], "3.0.3");
    assert_eq!(
        spec["paths"]["/api/openapi.json"]["get"]["x-token-allowed"],
        true
    );
    assert_eq!(spec["paths"].as_object().unwrap().len(), 1);
    assert!(
        std::fs::read_to_string(directory.path().join("API.md"))?.contains("/api/openapi.json")
    );
    Ok(())
}
