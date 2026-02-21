use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn send_and_receive(messages: &[&str], expected_responses: usize) -> Vec<serde_json::Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_safe-pkgs"))
        .args(["serve", "--mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start safe-pkgs");

    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();

    let owned_messages: Vec<String> = messages.iter().map(|s| s.to_string()).collect();
    let writer = std::thread::spawn(move || {
        let mut stdin = stdin;
        for msg in &owned_messages {
            writeln!(stdin, "{msg}").unwrap();
            stdin.flush().unwrap();
        }
        // Keep stdin open long enough for network-backed checks to finish.
        std::thread::sleep(std::time::Duration::from_secs(5));
        drop(stdin);
    });

    let reader = BufReader::new(stdout);
    let mut responses = Vec::new();
    for line in reader.lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            responses.push(val);
            if responses.len() >= expected_responses {
                break;
            }
        }
    }

    writer.join().unwrap();
    let _ = child.kill();
    let _ = child.wait();
    responses
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const LIST_TOOLS: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;

fn call_check_package(id: u64, args: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"check_package","arguments":{args}}}}}"#
    )
}

fn call_check_lockfile(id: u64, path: &str, registry: Option<&str>) -> String {
    let path_json = serde_json::to_string(path).expect("path JSON encoding");
    let registry_json = registry.map(|value| {
        let registry_json = serde_json::to_string(value).expect("registry JSON encoding");
        format!(r#","registry":{}"#, registry_json)
    });
    let registry_json = registry_json.unwrap_or_default();
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"check_lockfile","arguments":{{"path":{path_json}{registry_json}}}}}}}"#
    )
}

#[test]
fn initialize_returns_tools_capability() {
    let responses = send_and_receive(&[INIT], 1);
    let init_resp = &responses[0];
    assert_eq!(init_resp["id"], 1);
    assert!(init_resp["result"]["capabilities"]["tools"].is_object());
    assert_eq!(
        init_resp["result"]["protocolVersion"].as_str().unwrap(),
        "2024-11-05"
    );
}

#[test]
fn list_tools_contains_check_package() {
    let responses = send_and_receive(&[INIT, INITIALIZED, LIST_TOOLS], 2);
    let tools_resp = responses.iter().find(|r| r["id"] == 2).unwrap();
    let tools = tools_resp["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    let tool_names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(tool_names.contains(&"check_package"));
    assert!(tool_names.contains(&"check_lockfile"));

    let check_package = tools
        .iter()
        .find(|tool| tool["name"] == "check_package")
        .expect("check_package tool");
    let required = check_package["inputSchema"]["required"].as_array().unwrap();
    let required: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(required.contains(&"name"));
}

#[test]
fn call_check_package_with_version() {
    let call = call_check_package(3, r#"{"name":"lodash","version":"4.17.21"}"#);
    let responses = send_and_receive(&[INIT, INITIALIZED, &call], 2);
    let call_resp = responses.iter().find(|r| r["id"] == 3).unwrap();

    assert_eq!(call_resp["result"]["isError"], false);
    let text = call_resp["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(body["allow"].is_boolean());
    assert!(body["risk"].is_string());
    assert!(body["reasons"].is_array());
    assert_eq!(body["metadata"]["requested"], "4.17.21");
}

#[test]
fn call_check_package_name_only() {
    let call = call_check_package(3, r#"{"name":"express"}"#);
    let responses = send_and_receive(&[INIT, INITIALIZED, &call], 2);
    let call_resp = responses.iter().find(|r| r["id"] == 3).unwrap();

    let text = call_resp["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(body["allow"].is_boolean());
    assert!(body["risk"].is_string());
    assert!(body["metadata"]["requested"].is_null());
}

#[test]
fn call_check_package_for_cargo_registry() {
    let call = call_check_package(
        3,
        r#"{"name":"serde","version":"1.0.100","registry":"cargo"}"#,
    );
    let responses = send_and_receive(&[INIT, INITIALIZED, &call], 2);
    let call_resp = responses.iter().find(|r| r["id"] == 3).unwrap();

    assert_eq!(call_resp["result"]["isError"], false);
    let text = call_resp["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["allow"], true);
    assert_eq!(body["metadata"]["requested"], "1.0.100");
    assert!(body["metadata"]["latest"].is_string());
}

#[test]
fn call_check_package_for_pypi_registry() {
    let call = call_check_package(
        3,
        r#"{"name":"requests","version":"2.31.0","registry":"pypi"}"#,
    );
    let responses = send_and_receive(&[INIT, INITIALIZED, &call], 2);
    let call_resp = responses.iter().find(|r| r["id"] == 3).unwrap();

    assert_eq!(call_resp["result"]["isError"], false);
    let text = call_resp["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(body["allow"].is_boolean());
    assert_eq!(body["metadata"]["requested"], "2.31.0");
    assert!(body["metadata"]["latest"].is_string());
}

#[test]
fn call_check_lockfile_for_empty_manifest() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let temp_dir = std::env::temp_dir().join(format!("safe-pkgs-lockfile-{unique}"));
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    let manifest_path = temp_dir.join("package.json");
    fs::write(
        &manifest_path,
        r#"{"name":"demo","version":"1.0.0","dependencies":{}}"#,
    )
    .expect("write package.json");

    let manifest_str = manifest_path.to_string_lossy();
    let call = call_check_lockfile(4, manifest_str.as_ref(), None);
    let responses = send_and_receive(&[INIT, INITIALIZED, &call], 2);
    let call_resp = responses.iter().find(|r| r["id"] == 4).unwrap();

    assert_eq!(call_resp["result"]["isError"], false);
    let text = call_resp["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["allow"], true);
    assert_eq!(body["risk"], "low");
    assert_eq!(body["total"], 0);
    assert_eq!(body["denied"], 0);

    let _ = fs::remove_file(manifest_path);
    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn call_check_lockfile_for_empty_pyproject_manifest() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let temp_dir = std::env::temp_dir().join(format!("safe-pkgs-py-lockfile-{unique}"));
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    let pyproject_path = temp_dir.join("pyproject.toml");
    fs::write(
        &pyproject_path,
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = []
"#,
    )
    .expect("write pyproject.toml");

    let path_str = pyproject_path.to_string_lossy();
    let call = call_check_lockfile(5, path_str.as_ref(), Some("pypi"));
    let responses = send_and_receive(&[INIT, INITIALIZED, &call], 2);
    let call_resp = responses.iter().find(|r| r["id"] == 5).unwrap();

    assert_eq!(call_resp["result"]["isError"], false);
    let text = call_resp["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["allow"], true);
    assert_eq!(body["risk"], "low");
    assert_eq!(body["total"], 0);
    assert_eq!(body["denied"], 0);

    let _ = fs::remove_file(pyproject_path);
    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn call_check_lockfile_for_empty_cargo_manifest() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let temp_dir = std::env::temp_dir().join(format!("safe-pkgs-cargo-lockfile-{unique}"));
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    let cargo_path = temp_dir.join("Cargo.toml");
    fs::write(
        &cargo_path,
        r#"[package]
name = "demo"
version = "0.1.0"
edition = "2021"
"#,
    )
    .expect("write Cargo.toml");

    let path_str = cargo_path.to_string_lossy();
    let call = call_check_lockfile(6, path_str.as_ref(), Some("cargo"));
    let responses = send_and_receive(&[INIT, INITIALIZED, &call], 2);
    let call_resp = responses.iter().find(|r| r["id"] == 6).unwrap();

    assert_eq!(call_resp["result"]["isError"], false);
    let text = call_resp["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["allow"], true);
    assert_eq!(body["risk"], "low");
    assert_eq!(body["total"], 0);
    assert_eq!(body["denied"], 0);

    let _ = fs::remove_file(cargo_path);
    let _ = fs::remove_dir_all(temp_dir);
}
