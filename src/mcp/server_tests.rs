use super::*;
use crate::config::SafePkgsConfig;

#[test]
fn tool_is_registered() {
    let server = SafePkgsServer::with_config(SafePkgsConfig::default());
    let package_tool = server.get_tool("check_package");
    assert!(package_tool.is_some());
    let package_tool = package_tool.expect("check_package exists");
    assert_eq!(package_tool.name.as_ref(), "check_package");
    assert!(
        package_tool
            .description
            .as_ref()
            .expect("description")
            .contains("safe to install")
    );

    let lockfile_tool = server.get_tool("check_lockfile");
    assert!(lockfile_tool.is_some());
    let lockfile_tool = lockfile_tool.expect("check_lockfile exists");
    assert_eq!(lockfile_tool.name.as_ref(), "check_lockfile");
    assert!(
        lockfile_tool
            .description
            .as_ref()
            .expect("description")
            .contains("Batch-check dependencies")
    );
}

#[test]
fn tool_schema_has_required_name() {
    let server = SafePkgsServer::with_config(SafePkgsConfig::default());
    let tool = server.get_tool("check_package").expect("tool");
    let schema = tool.input_schema;
    let required = schema
        .get("required")
        .expect("required key")
        .as_array()
        .expect("required array");
    let required: Vec<&str> = required
        .iter()
        .map(|v| v.as_str().expect("required key as str"))
        .collect();
    assert!(required.contains(&"name"));
    assert!(!required.contains(&"version"));
    assert!(!required.contains(&"registry"));
}

#[test]
fn tool_schema_exposes_registry_enum_values() {
    let server = SafePkgsServer::with_config(SafePkgsConfig::default());
    let tool = server.get_tool("check_package").expect("tool");
    let properties = tool
        .input_schema
        .get("properties")
        .and_then(|v| v.as_object())
        .expect("properties object");
    let registry = properties
        .get("registry")
        .and_then(|v| v.as_object())
        .expect("registry property");
    assert_eq!(
        registry.get("type").and_then(|v| v.as_str()),
        Some("string")
    );
    let values = registry
        .get("enum")
        .and_then(|v| v.as_array())
        .expect("registry enum");
    let values: Vec<&str> = values.iter().filter_map(|v| v.as_str()).collect();
    assert!(values.contains(&"npm"));
    assert!(values.contains(&"cargo"));
    assert!(values.contains(&"pypi"));
}

#[test]
fn lockfile_tool_schema_exposes_supported_registry_values() {
    let server = SafePkgsServer::with_config(SafePkgsConfig::default());
    let tool = server.get_tool("check_lockfile").expect("tool");
    let properties = tool
        .input_schema
        .get("properties")
        .and_then(|v| v.as_object())
        .expect("properties object");
    let registry = properties
        .get("registry")
        .and_then(|v| v.as_object())
        .expect("registry property");
    let values = registry
        .get("enum")
        .and_then(|v| v.as_array())
        .expect("registry enum");
    let values: Vec<&str> = values.iter().filter_map(|v| v.as_str()).collect();
    assert!(values.contains(&"npm"));
    assert!(values.contains(&"cargo"));
    assert!(values.contains(&"pypi"));
}

#[test]
fn server_info_enables_tools() {
    let server = SafePkgsServer::with_config(SafePkgsConfig::default());
    let info = server.get_info();
    assert!(info.capabilities.tools.is_some());
    assert!(
        info.instructions
            .expect("instructions")
            .contains("check_lockfile")
    );
}

#[test]
fn validate_package_query_rejects_empty_name() {
    let query = PackageQuery {
        name: "   ".to_string(),
        version: Some("1.0.0".to_string()),
        registry: "npm".to_string(),
    };
    assert!(validate_package_query(&query).is_err());
}

#[test]
fn validate_package_query_rejects_empty_version() {
    let query = PackageQuery {
        name: "lodash".to_string(),
        version: Some(" ".to_string()),
        registry: "npm".to_string(),
    };
    assert!(validate_package_query(&query).is_err());
}

#[test]
fn validate_lockfile_query_rejects_empty_path() {
    let query = LockfileQuery {
        path: Some(" ".to_string()),
        registry: "npm".to_string(),
    };
    assert!(validate_lockfile_query(&query).is_err());
}
