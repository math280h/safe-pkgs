use safe_pkgs_core::{DependencySpec, LockfileError, LockfileParser};
use std::collections::BTreeMap;
use std::path::Path;
use toml::Value;

#[derive(Debug, Clone, Default)]
pub struct CargoLockfileParser;

impl CargoLockfileParser {
    pub fn new() -> Self {
        Self
    }
}

impl LockfileParser for CargoLockfileParser {
    fn supported_files(&self) -> &'static [&'static str] {
        &["Cargo.lock", "Cargo.toml"]
    }

    fn parse_dependencies(&self, path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
        parse_cargo_dependencies(path)
    }
}

fn parse_cargo_dependencies(path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(LockfileError::InvalidInputPath {
            path: path.display().to_string(),
        });
    };

    match file_name {
        "Cargo.lock" => parse_cargo_lock(path),
        "Cargo.toml" => parse_cargo_manifest(path),
        _ => Err(LockfileError::UnsupportedFile {
            file_name: file_name.to_string(),
            expected: "Cargo.lock, Cargo.toml".to_string(),
        }),
    }
}

fn parse_cargo_lock(path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
    let raw = std::fs::read_to_string(path).map_err(|source| LockfileError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    let root: Value = toml::from_str(&raw).map_err(|error| LockfileError::ParseFile {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;

    let mut dependencies = BTreeMap::<String, Option<String>>::new();
    let packages = root
        .get("package")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    for package in packages {
        let Some(table) = package.as_table() else {
            continue;
        };
        let Some(name) = table
            .get("name")
            .and_then(|value| value.as_str())
            .and_then(normalize_crate_name)
        else {
            continue;
        };
        if !is_crates_io_source(table.get("source").and_then(|value| value.as_str())) {
            continue;
        }
        let version = table
            .get("version")
            .and_then(|value| value.as_str())
            .and_then(normalize_cargo_exact_version);
        insert_dependency_spec(
            &mut dependencies,
            DependencySpec {
                name: name.to_string(),
                version,
            },
        );
    }

    Ok(dependencies
        .into_iter()
        .map(|(name, version)| DependencySpec { name, version })
        .collect())
}

fn parse_cargo_manifest(path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
    let raw = std::fs::read_to_string(path).map_err(|source| LockfileError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    let root: Value = toml::from_str(&raw).map_err(|error| LockfileError::ParseFile {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;

    let mut dependencies = BTreeMap::<String, Option<String>>::new();
    parse_manifest_dependency_section(root.get("dependencies"), &mut dependencies);
    parse_manifest_dependency_section(root.get("dev-dependencies"), &mut dependencies);
    parse_manifest_dependency_section(root.get("build-dependencies"), &mut dependencies);
    parse_manifest_dependency_section(
        root.get("workspace")
            .and_then(|value| value.get("dependencies")),
        &mut dependencies,
    );

    if let Some(targets) = root.get("target").and_then(|value| value.as_table()) {
        for target in targets.values() {
            parse_manifest_dependency_section(target.get("dependencies"), &mut dependencies);
            parse_manifest_dependency_section(target.get("dev-dependencies"), &mut dependencies);
            parse_manifest_dependency_section(target.get("build-dependencies"), &mut dependencies);
        }
    }

    Ok(dependencies
        .into_iter()
        .map(|(name, version)| DependencySpec { name, version })
        .collect())
}

fn parse_manifest_dependency_section(
    section: Option<&Value>,
    dependencies: &mut BTreeMap<String, Option<String>>,
) {
    let Some(table) = section.and_then(|value| value.as_table()) else {
        return;
    };

    for (declared_name, value) in table {
        let Some(spec) = parse_manifest_dependency(declared_name, value) else {
            continue;
        };
        insert_dependency_spec(dependencies, spec);
    }
}

fn parse_manifest_dependency(declared_name: &str, value: &Value) -> Option<DependencySpec> {
    match value {
        Value::String(raw_version) => Some(DependencySpec {
            name: normalize_crate_name(declared_name)?.to_string(),
            version: normalize_cargo_manifest_version(raw_version),
        }),
        Value::Table(entries) => {
            if !manifest_dependency_is_supported_registry(entries) {
                return None;
            }
            let name = entries
                .get("package")
                .and_then(|value| value.as_str())
                .and_then(normalize_crate_name)
                .or_else(|| normalize_crate_name(declared_name))?;
            let version = entries
                .get("version")
                .and_then(|value| value.as_str())
                .and_then(normalize_cargo_manifest_version);
            Some(DependencySpec {
                name: name.to_string(),
                version,
            })
        }
        _ => None,
    }
}

fn manifest_dependency_is_supported_registry(entries: &toml::value::Table) -> bool {
    if entries.contains_key("path") || entries.contains_key("git") {
        return false;
    }
    if entries.get("workspace").and_then(|value| value.as_bool()) == Some(true) {
        return false;
    }
    if let Some(registry) = entries.get("registry").and_then(|value| value.as_str()) {
        return registry.eq_ignore_ascii_case("crates-io");
    }
    true
}

fn normalize_crate_name(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return None;
    }

    Some(trimmed)
}

fn normalize_cargo_exact_version(raw: &str) -> Option<String> {
    let candidate = raw.trim();
    if candidate.is_empty() || candidate.contains(' ') {
        return None;
    }
    Some(candidate.to_string())
}

fn normalize_cargo_manifest_version(raw: &str) -> Option<String> {
    let candidate = raw.trim();
    if candidate.is_empty() || candidate == "*" {
        return None;
    }

    let exact = candidate.strip_prefix('=').unwrap_or(candidate).trim();
    if exact.is_empty() {
        return None;
    }

    if exact.contains('*')
        || exact.contains(' ')
        || exact.contains('^')
        || exact.contains('~')
        || exact.contains('<')
        || exact.contains('>')
        || exact.contains(',')
        || exact.contains('|')
    {
        return None;
    }

    Some(exact.to_string())
}

fn is_crates_io_source(raw: Option<&str>) -> bool {
    let Some(value) = raw.map(str::trim) else {
        return false;
    };
    value.starts_with("registry+")
        && (value.contains("crates.io") || value.contains("index.crates.io"))
}

fn insert_dependency_spec(
    dependencies: &mut BTreeMap<String, Option<String>>,
    spec: DependencySpec,
) {
    dependencies
        .entry(spec.name)
        .and_modify(|existing| {
            if existing.is_none() && spec.version.is_some() {
                *existing = spec.version.clone();
            }
        })
        .or_insert(spec.version);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("safe-pkgs-cargo-lockfile-{nanos}-{suffix}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn find_version<'a>(deps: &'a [DependencySpec], name: &str) -> Option<&'a str> {
        deps.iter()
            .find(|spec| spec.name == name)
            .and_then(|spec| spec.version.as_deref())
    }

    #[test]
    fn supported_files_lists_cargo_inputs() {
        let parser = CargoLockfileParser::new();
        assert_eq!(parser.supported_files(), ["Cargo.lock", "Cargo.toml"]);
    }

    #[test]
    fn parse_dependencies_dispatches_by_filename() {
        let parser = CargoLockfileParser::new();
        let dir = unique_temp_dir("dispatch");
        let lock_path = dir.join("Cargo.lock");
        let manifest_path = dir.join("Cargo.toml");
        std::fs::write(
            &lock_path,
            r#"
version = 3

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect("write lock");
        std::fs::write(
            &manifest_path,
            r#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
tokio = "1.0.0"
"#,
        )
        .expect("write manifest");

        let lock = parser.parse_dependencies(&lock_path).expect("parse lock");
        let manifest = parser
            .parse_dependencies(&manifest_path)
            .expect("parse manifest");
        assert_eq!(find_version(&lock, "serde"), Some("1.0.210"));
        assert_eq!(find_version(&manifest, "tokio"), Some("1.0.0"));

        let _ = std::fs::remove_file(lock_path);
        let _ = std::fs::remove_file(manifest_path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_cargo_lock_includes_only_crates_io_registry_packages() {
        let dir = unique_temp_dir("lock");
        let path = dir.join("Cargo.lock");
        std::fs::write(
            &path,
            r#"
version = 3

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "custom-registry-pkg"
version = "0.1.0"
source = "registry+https://custom.example/index"

[[package]]
name = "git-only"
version = "0.2.0"
source = "git+https://example.com/repo#deadbeef"

[[package]]
name = "local-workspace"
version = "0.1.0"
"#,
        )
        .expect("write lock");

        let deps = parse_cargo_lock(&path).expect("parse lock");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version.as_deref(), Some("1.0.210"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_cargo_manifest_parses_supported_dependency_sections() {
        let dir = unique_temp_dir("manifest");
        let path = dir.join("Cargo.toml");
        std::fs::write(
            &path,
            r#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0.210"
renamed = { package = "regex", version = "=1.10.6" }
local_dep = { path = "../local" }
git_dep = { git = "https://example.com/repo.git" }
workspace_dep = { workspace = true }
private_dep = { version = "1.0.0", registry = "private" }
cc = "^1.0"

[dev-dependencies]
tempfile = { version = "=3.12.0" }

[target.'cfg(unix)'.dependencies]
libc = "0.2.155"

[workspace.dependencies]
tracing = "0.1.40"
"#,
        )
        .expect("write manifest");

        let deps = parse_cargo_manifest(&path).expect("parse manifest");
        assert_eq!(find_version(&deps, "serde"), Some("1.0.210"));
        assert_eq!(find_version(&deps, "regex"), Some("1.10.6"));
        assert_eq!(find_version(&deps, "tempfile"), Some("3.12.0"));
        assert_eq!(find_version(&deps, "libc"), Some("0.2.155"));
        assert_eq!(find_version(&deps, "tracing"), Some("0.1.40"));
        assert_eq!(find_version(&deps, "cc"), None);
        assert!(deps.iter().all(|dep| dep.name != "local_dep"));
        assert!(deps.iter().all(|dep| dep.name != "git_dep"));
        assert!(deps.iter().all(|dep| dep.name != "workspace_dep"));
        assert!(deps.iter().all(|dep| dep.name != "private_dep"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_cargo_manifest_rejects_invalid_toml() {
        let dir = unique_temp_dir("manifest-invalid");
        let path = dir.join("Cargo.toml");
        std::fs::write(&path, "[package\nname=").expect("write invalid toml");

        let err = parse_cargo_manifest(&path).expect_err("invalid manifest should fail");
        assert!(matches!(err, LockfileError::ParseFile { .. }));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_cargo_lock_rejects_invalid_toml() {
        let dir = unique_temp_dir("lock-invalid");
        let path = dir.join("Cargo.lock");
        std::fs::write(&path, "[package\nname=").expect("write invalid toml");

        let err = parse_cargo_lock(&path).expect_err("invalid lockfile should fail");
        assert!(matches!(err, LockfileError::ParseFile { .. }));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_cargo_dependencies_rejects_unsupported_filename() {
        let dir = unique_temp_dir("unsupported");
        let path = dir.join("poetry.lock");
        std::fs::write(&path, "").expect("write file");

        let err = parse_cargo_dependencies(&path).expect_err("unsupported file should fail");
        assert!(matches!(err, LockfileError::UnsupportedFile { .. }));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn normalize_manifest_version_keeps_exact_pins_only() {
        assert_eq!(
            normalize_cargo_manifest_version("=1.2.3"),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            normalize_cargo_manifest_version("1.2.3"),
            Some("1.2.3".to_string())
        );
        assert_eq!(normalize_cargo_manifest_version("^1.2"), None);
        assert_eq!(normalize_cargo_manifest_version("~1.2"), None);
        assert_eq!(normalize_cargo_manifest_version("*"), None);
    }
}
