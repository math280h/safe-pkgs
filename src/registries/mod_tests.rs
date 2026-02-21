use super::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_path(file_name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!("safe-pkgs-registry-tests-{nanos}-{file_name}"))
}

#[test]
fn check_support_map_marks_install_scripts_only_for_npm() {
    let catalog = register_default_catalog();
    let rows = catalog.check_support_rows();

    let npm_install_script = rows
        .iter()
        .find(|row| row.registry == "npm" && row.check == "install_script")
        .expect("npm install_script row");
    let cargo_install_script = rows
        .iter()
        .find(|row| row.registry == "cargo" && row.check == "install_script")
        .expect("cargo install_script row");
    let pypi_install_script = rows
        .iter()
        .find(|row| row.registry == "pypi" && row.check == "install_script")
        .expect("pypi install_script row");

    assert!(npm_install_script.supported);
    assert!(!cargo_install_script.supported);
    assert!(!pypi_install_script.supported);
}

#[test]
fn check_support_map_has_every_registry_check_pair() {
    let catalog = register_default_catalog();
    let rows = catalog.check_support_rows();
    let check_count = crate::checks::check_descriptors().len();

    let expected = supported_package_registry_keys().len() * check_count;
    assert_eq!(rows.len(), expected);
}

#[test]
fn supported_lockfile_files_are_exposed_per_registry() {
    let npm_files = supported_lockfile_files_for_registry("npm").expect("npm lockfile files");
    let cargo_files = supported_lockfile_files_for_registry("cargo").expect("cargo lockfile files");
    let pypi_files = supported_lockfile_files_for_registry("pypi").expect("pypi lockfile files");

    assert!(npm_files.contains(&"package-lock.json"));
    assert!(cargo_files.contains(&"Cargo.lock"));
    assert!(pypi_files.contains(&"requirements.txt"));
    assert!(supported_lockfile_files_for_registry("unknown").is_none());
}

#[test]
fn validate_lockfile_request_rejects_unknown_registry_and_empty_path() {
    let unknown = validate_lockfile_request("unknown", None).expect_err("unknown registry");
    assert!(unknown.contains("unsupported lockfile registry"));

    let empty_path =
        validate_lockfile_request("npm", Some(" ")).expect_err("empty path should fail");
    assert!(empty_path.contains("path must not be an empty string"));
}

#[test]
fn validate_lockfile_request_rejects_unsupported_existing_file() {
    let dir = unique_temp_path("validate-unsupported");
    fs::create_dir_all(&dir).expect("create temp dir");
    let file = dir.join("requirements.txt");
    fs::write(&file, "requests==2.31.0").expect("write file");

    let err = validate_lockfile_request("cargo", Some(file.to_string_lossy().as_ref()))
        .expect_err("unsupported file for cargo");
    assert!(err.contains("unsupported dependency file"));

    let _ = fs::remove_file(file);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn validate_lockfile_request_accepts_supported_existing_file() {
    let dir = unique_temp_path("validate-supported");
    fs::create_dir_all(&dir).expect("create temp dir");
    let file = dir.join("Cargo.lock");
    fs::write(&file, "version = 3").expect("write file");

    let result = validate_lockfile_request("cargo", Some(file.to_string_lossy().as_ref()));
    assert!(result.is_ok());

    let _ = fs::remove_file(file);
    let _ = fs::remove_dir_all(dir);
}
