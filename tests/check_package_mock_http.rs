use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{Duration, Utc};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn send_and_receive_with_env(
    messages: &[&str],
    expected_responses: usize,
    envs: &[(&str, &str)],
) -> Vec<serde_json::Value> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_safe-pkgs"));
    cmd.args(["serve", "--mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (key, value) in envs {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().expect("failed to start safe-pkgs");

    let stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

    let owned_messages: Vec<String> = messages.iter().map(|s| s.to_string()).collect();
    let writer = std::thread::spawn(move || {
        let mut stdin = stdin;
        for msg in &owned_messages {
            writeln!(stdin, "{msg}").expect("write message");
            stdin.flush().expect("flush message");
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
        drop(stdin);
    });

    let reader = BufReader::new(stdout);
    let mut responses = Vec::new();
    for line in reader.lines() {
        let line = line.expect("line read");
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

    writer.join().expect("writer join");
    let _ = child.kill();
    let _ = child.wait();
    responses
}

fn unique_temp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!("safe-pkgs-{nanos}-{name}"))
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn call_check_package(id: u64, args: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"check_package","arguments":{args}}}}}"#
    )
}

#[tokio::test]
async fn check_package_uses_mock_http_endpoints() {
    let mock_server = MockServer::start().await;

    let published = (Utc::now() - Duration::days(10)).to_rfc3339();
    let package_payload = serde_json::json!({
        "dist-tags": { "latest": "1.0.0" },
        "maintainers": [{ "name": "trusted-publisher" }],
        "versions": {
            "1.0.0": {
                "scripts": {}
            }
        },
        "time": {
            "1.0.0": published
        }
    });

    Mock::given(method("GET"))
        .and(path("/demo-lib"))
        .respond_with(ResponseTemplate::new(200).set_body_json(package_payload))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/downloads/point/last-week/demo-lib"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "downloads": 1000
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "vulns": []
        })))
        .mount(&mock_server)
        .await;

    let config_path = unique_temp_path("config.toml");
    fs::write(
        &config_path,
        r#"
max_risk = "medium"

[staleness]
warn_age_days = 100000
"#,
    )
    .expect("write config");

    let project_config_path = unique_temp_path("project-config.toml");
    let cache_path = unique_temp_path("cache.db");
    let mock_uri = mock_server.uri();
    let osv_url = format!("{mock_uri}/v1/query");
    let config_path_value = config_path.to_string_lossy().to_string();
    let project_config_value = project_config_path.to_string_lossy().to_string();
    let cache_path_value = cache_path.to_string_lossy().to_string();

    let check_call = call_check_package(3, r#"{"name":"demo-lib","version":"1.0.0"}"#);
    let responses = send_and_receive_with_env(
        &[INIT, INITIALIZED, &check_call],
        2,
        &[
            ("SAFE_PKGS_NPM_REGISTRY_API_BASE_URL", mock_uri.as_str()),
            ("SAFE_PKGS_NPM_DOWNLOADS_API_BASE_URL", mock_uri.as_str()),
            (
                "SAFE_PKGS_NPM_POPULAR_INDEX_API_BASE_URL",
                mock_uri.as_str(),
            ),
            ("SAFE_PKGS_OSV_API_BASE_URL", osv_url.as_str()),
            ("SAFE_PKGS_CONFIG_GLOBAL_PATH", config_path_value.as_str()),
            (
                "SAFE_PKGS_CONFIG_PROJECT_PATH",
                project_config_value.as_str(),
            ),
            ("SAFE_PKGS_CACHE_DB_PATH", cache_path_value.as_str()),
        ],
    );

    let call_resp = responses.iter().find(|item| item["id"] == 3).expect("call");
    assert_eq!(call_resp["result"]["isError"], false);
    let text = call_resp["result"]["content"][0]["text"]
        .as_str()
        .expect("tool body");
    let body: serde_json::Value = serde_json::from_str(text).expect("response json");
    assert_eq!(body["allow"], true);
    assert_eq!(body["risk"], "low");
    assert_eq!(body["metadata"]["latest"], "1.0.0");
    assert_eq!(body["metadata"]["requested"], "1.0.0");
    assert_eq!(body["metadata"]["weekly_downloads"], 1000);

    let _ = fs::remove_file(config_path);
    let _ = fs::remove_file(cache_path);
}
