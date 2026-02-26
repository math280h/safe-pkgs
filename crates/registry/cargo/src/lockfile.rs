use safe_pkgs_core::{DependencySpec, LockfileError, LockfileParser};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
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

    let mut nodes = BTreeMap::<String, LockNode>::new();
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
            .map(ToOwned::to_owned)
        else {
            continue;
        };

        let source = table.get("source").and_then(|value| value.as_str());
        let workspace_root = source.is_none();
        let lock_dependencies =
            parse_cargo_lock_dependency_names(table.get("dependencies")).collect::<BTreeSet<_>>();

        nodes
            .entry(name.clone())
            .and_modify(|node| {
                if workspace_root {
                    node.workspace_root = true;
                }
                node.dependencies.extend(lock_dependencies.clone());
            })
            .or_insert_with(|| LockNode {
                dependencies: lock_dependencies,
                workspace_root,
            });

        if !is_crates_io_source(source) {
            continue;
        }

        let version = table
            .get("version")
            .and_then(|value| value.as_str())
            .and_then(normalize_cargo_exact_version);
        insert_dependency_spec(&mut dependencies, direct_dependency_spec(name, version));
    }

    let roots = lockfile_root_packages(&nodes);
    let shortest_paths = compute_shortest_paths(&nodes, &roots);

    Ok(dependencies
        .into_iter()
        .map(|(name, version)| {
            let mut spec = direct_dependency_spec(name.clone(), version);
            if let Some(path) = shortest_paths.get(&name) {
                spec.dependency_paths = parent_chain_from_full_path(path);
            }
            spec
        })
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
        .map(|(name, version)| direct_dependency_spec(name, version))
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
        Value::String(raw_version) => Some(direct_dependency_spec(
            normalize_crate_name(declared_name)?.to_string(),
            normalize_cargo_manifest_version(raw_version),
        )),
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
            Some(direct_dependency_spec(name.to_string(), version))
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

/// Extracts normalized dependency package names from a `Cargo.lock` dependency array.
///
/// Invalid or unparsable entries are skipped.
fn parse_cargo_lock_dependency_names(raw: Option<&Value>) -> impl Iterator<Item = String> {
    raw.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(parse_cargo_lock_dependency_name)
}

fn parse_cargo_lock_dependency_name(raw: &str) -> Option<String> {
    let name = raw.split_whitespace().next()?;
    normalize_crate_name(name).map(ToOwned::to_owned)
}

/// Identifies root packages for lockfile graph traversal.
///
/// Prefers workspace root packages when present. Otherwise selects packages with
/// no incoming edges. If no clear roots exist (for example, cyclic graphs),
/// falls back to all known package nodes.
fn lockfile_root_packages(nodes: &BTreeMap<String, LockNode>) -> Vec<String> {
    let mut roots = nodes
        .iter()
        .filter(|(_, node)| node.workspace_root)
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();

    if !roots.is_empty() {
        return roots;
    }

    let mut incoming = nodes
        .keys()
        .map(|name| (name.clone(), 0usize))
        .collect::<BTreeMap<_, _>>();
    for node in nodes.values() {
        for dep in &node.dependencies {
            if let Some(count) = incoming.get_mut(dep) {
                *count = count.saturating_add(1);
            }
        }
    }

    roots = incoming
        .into_iter()
        .filter(|(_, count)| *count == 0)
        .map(|(name, _)| name)
        .collect();
    if roots.is_empty() {
        return nodes.keys().cloned().collect();
    }
    roots
}

/// Performs breadth-first search from root packages to compute shortest paths.
///
/// Returns one shortest full path (including target) per reachable package.
fn compute_shortest_paths(
    nodes: &BTreeMap<String, LockNode>,
    roots: &[String],
) -> BTreeMap<String, Vec<String>> {
    let mut shortest_paths = BTreeMap::<String, Vec<String>>::new();
    let mut queue = VecDeque::<String>::new();

    for root in roots {
        if !nodes.contains_key(root) {
            continue;
        }
        if shortest_paths.contains_key(root) {
            continue;
        }
        shortest_paths.insert(root.clone(), vec![root.clone()]);
        queue.push_back(root.clone());
    }

    while let Some(current) = queue.pop_front() {
        let current_path = shortest_paths
            .get(&current)
            .cloned()
            .unwrap_or_else(|| vec![current.clone()]);
        let Some(node) = nodes.get(&current) else {
            continue;
        };

        for dep in &node.dependencies {
            if !nodes.contains_key(dep) || shortest_paths.contains_key(dep) {
                continue;
            }
            let mut path = current_path.clone();
            path.push(dep.clone());
            shortest_paths.insert(dep.clone(), path);
            queue.push_back(dep.clone());
        }
    }

    shortest_paths
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

/// Builds a `DependencySpec` for a direct (non-transitive) dependency.
///
/// Direct dependencies carry no ancestry path, so `dependency_paths` is empty.
fn direct_dependency_spec(name: String, version: Option<String>) -> DependencySpec {
    DependencySpec {
        dependency_paths: Vec::new(),
        name,
        version,
    }
}

/// Converts a full dependency path into parent ancestry for output.
///
/// Excludes the target package itself and returns an empty result for direct
/// dependencies (`path.len() <= 1`).
fn parent_chain_from_full_path(path: &[String]) -> Vec<Vec<String>> {
    if path.len() <= 1 {
        return Vec::new();
    }
    vec![path[..path.len() - 1].to_vec()]
}

#[derive(Debug, Clone, Default)]
struct LockNode {
    dependencies: BTreeSet<String>,
    workspace_root: bool,
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

    fn find_paths(deps: &[DependencySpec], name: &str) -> Option<Vec<Vec<String>>> {
        deps.iter()
            .find(|spec| spec.name == name)
            .map(|spec| spec.dependency_paths.clone())
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
        assert_eq!(find_paths(&manifest, "tokio"), Some(vec![]));

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
    fn parse_cargo_lock_builds_shortest_paths_from_workspace_roots() {
        let dir = unique_temp_dir("lock-paths");
        let path = dir.join("Cargo.lock");
        std::fs::write(
            &path,
            r#"
version = 3

[[package]]
name = "workspace-app"
version = "0.1.0"
dependencies = [
 "serde 1.0.210 (registry+https://github.com/rust-lang/crates.io-index)"
]

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "serde_derive 1.0.210 (registry+https://github.com/rust-lang/crates.io-index)"
]

[[package]]
name = "serde_derive"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect("write lock");

        let deps = parse_cargo_lock(&path).expect("parse lock");
        assert_eq!(
            find_paths(&deps, "serde"),
            Some(vec![vec!["workspace-app".to_string()]])
        );
        assert_eq!(
            find_paths(&deps, "serde_derive"),
            Some(vec![vec!["workspace-app".to_string(), "serde".to_string()]])
        );

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
