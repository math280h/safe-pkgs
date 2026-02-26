use safe_pkgs_core::{DependencySpec, LockfileError, LockfileParser};
use semver::Version;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct NpmLockfileParser;

impl NpmLockfileParser {
    pub fn new() -> Self {
        Self
    }
}

impl LockfileParser for NpmLockfileParser {
    fn supported_files(&self) -> &'static [&'static str] {
        &["package-lock.json", "package.json"]
    }

    fn parse_dependencies(&self, path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
        parse_npm_dependencies(path)
    }
}

fn parse_npm_dependencies(path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(LockfileError::InvalidInputPath {
            path: path.display().to_string(),
        });
    };

    match file_name {
        "package-lock.json" => parse_package_lock(path),
        "package.json" => parse_package_manifest(path),
        _ => Err(LockfileError::UnsupportedFile {
            file_name: file_name.to_string(),
            expected: "package-lock.json, package.json".to_string(),
        }),
    }
}

fn parse_package_lock(path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
    let raw = std::fs::read_to_string(path).map_err(|source| LockfileError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    let root: serde_json::Value =
        serde_json::from_str(&raw).map_err(|error| LockfileError::ParseFile {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    let mut dependencies = BTreeMap::<String, LockDependencyRecord>::new();

    if let Some(top_level) = root.get("dependencies").and_then(|value| value.as_object()) {
        for (raw_name, value) in top_level {
            collect_dependency_tree(raw_name, value, &[], &mut dependencies);
        }
    }

    if let Some(packages) = root.get("packages").and_then(|value| value.as_object()) {
        for (module_path, value) in packages {
            let Some(path) = extract_dependency_path_from_node_modules_path(module_path) else {
                continue;
            };
            let Some(name) = path.last().cloned() else {
                continue;
            };
            let ancestry = path[..path.len() - 1].to_vec();
            let raw_version = value
                .as_object()
                .and_then(|obj| obj.get("version"))
                .and_then(|version| version.as_str());
            upsert_dependency(
                &mut dependencies,
                name,
                raw_version.and_then(normalize_requested_version),
                ancestry,
            );
        }
    }

    Ok(dependencies
        .into_iter()
        .map(|(name, record)| DependencySpec {
            name,
            version: record.version,
            dependency_paths: record.dependency_paths.into_iter().collect(),
        })
        .collect())
}

fn parse_package_manifest(path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
    let raw = std::fs::read_to_string(path).map_err(|source| LockfileError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    let root: serde_json::Value =
        serde_json::from_str(&raw).map_err(|error| LockfileError::ParseFile {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    let mut dependencies = BTreeMap::<String, LockDependencyRecord>::new();

    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(items) = root.get(section).and_then(|value| value.as_object()) else {
            continue;
        };
        for (raw_name, raw_version) in items {
            let Some(name) = normalize_npm_package_name(raw_name) else {
                continue;
            };
            upsert_dependency(
                &mut dependencies,
                name.clone(),
                raw_version.as_str().and_then(normalize_requested_version),
                Vec::new(),
            );
        }
    }

    Ok(dependencies
        .into_iter()
        .map(|(name, record)| DependencySpec {
            dependency_paths: record.dependency_paths.into_iter().collect(),
            name,
            version: record.version,
        })
        .collect())
}

/// Recursively walks npm `dependencies` tree entries and collects ancestry.
///
/// As traversal descends, parent package names are accumulated into ancestry
/// paths for each discovered dependency.
fn collect_dependency_tree(
    raw_name: &str,
    value: &serde_json::Value,
    parent_path: &[String],
    dependencies: &mut BTreeMap<String, LockDependencyRecord>,
) {
    let Some(name) = normalize_npm_package_name(raw_name) else {
        return;
    };

    let ancestry = parent_path.to_vec();
    let raw_version = value
        .as_object()
        .and_then(|obj| obj.get("version"))
        .and_then(|version| version.as_str())
        .or_else(|| value.as_str());
    upsert_dependency(
        dependencies,
        name.clone(),
        raw_version.and_then(normalize_requested_version),
        ancestry.clone(),
    );

    let mut child_path = ancestry;
    child_path.push(name);

    let Some(children) = value
        .as_object()
        .and_then(|obj| obj.get("dependencies"))
        .and_then(|value| value.as_object())
    else {
        return;
    };

    for (child_name, child_value) in children {
        collect_dependency_tree(child_name, child_value, &child_path, dependencies);
    }
}

/// Inserts or updates a dependency record and accumulates unique ancestry paths.
///
/// When updating, a non-`None` version is preferred over an existing `None`
/// version. Non-empty paths are deduplicated via the path set.
fn upsert_dependency(
    dependencies: &mut BTreeMap<String, LockDependencyRecord>,
    name: String,
    version: Option<String>,
    path: Vec<String>,
) {
    let record = dependencies.entry(name).or_default();
    if record.version.is_none() && version.is_some() {
        record.version = version;
    }

    if !path.is_empty() {
        record.dependency_paths.insert(path);
    }
}

/// Parses a `node_modules` path into normalized package-name segments.
///
/// Handles scoped package names and nested `node_modules` directories. Returns
/// `None` when the input does not encode a valid package path.
fn extract_dependency_path_from_node_modules_path(module_path: &str) -> Option<Vec<String>> {
    let normalized = module_path.replace('\\', "/");
    let segments = normalized
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return None;
    }

    let mut index = 0usize;
    let mut path = Vec::new();
    while index < segments.len() {
        if segments[index] != "node_modules" {
            index = index.saturating_add(1);
            continue;
        }

        index = index.saturating_add(1);
        if index >= segments.len() {
            return None;
        }

        if segments[index].starts_with('@') {
            if index + 1 >= segments.len() {
                return None;
            }
            let candidate = format!("{}/{}", segments[index], segments[index + 1]);
            let name = normalize_npm_package_name(candidate.as_str())?;
            path.push(name);
            index = index.saturating_add(2);
            continue;
        }

        let name = normalize_npm_package_name(segments[index])?;
        path.push(name);
        index = index.saturating_add(1);
    }

    if path.is_empty() { None } else { Some(path) }
}

fn normalize_npm_package_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('\\') {
        return None;
    }

    if trimmed.starts_with('@') {
        let (scope, name) = trimmed.split_once('/')?;
        if scope.len() <= 1 || name.is_empty() || name.contains('/') {
            return None;
        }

        let scope = normalize_npm_name_segment(scope.strip_prefix('@')?)?;
        let name = normalize_npm_name_segment(name)?;
        return Some(format!("@{scope}/{name}"));
    }

    if trimmed.contains('/') {
        return None;
    }

    normalize_npm_name_segment(trimmed)
}

fn normalize_npm_name_segment(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return None;
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

fn normalize_requested_version(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.eq_ignore_ascii_case("latest") {
        return Some("latest".to_string());
    }

    let candidate = trimmed.strip_prefix('=').unwrap_or(trimmed);
    if Version::parse(candidate).is_ok() {
        return Some(candidate.to_string());
    }

    None
}

#[derive(Debug, Clone, Default)]
struct LockDependencyRecord {
    version: Option<String>,
    dependency_paths: BTreeSet<Vec<String>>,
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
        let dir = std::env::temp_dir().join(format!("safe-pkgs-npm-lockfile-{nanos}-{suffix}"));
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
    fn package_manifest_parses_dependencies() {
        let dir = unique_temp_dir("manifest");
        let temp = dir.join("package.json");
        std::fs::write(
            &temp,
            r#"{"dependencies":{"a":"1.2.3"},"devDependencies":{"b":"^2.0.0"}}"#,
        )
        .expect("write temp file");

        let deps = parse_package_manifest(&temp).expect("parse package manifest");
        assert_eq!(deps.len(), 2);
        assert_eq!(find_version(&deps, "a"), Some("1.2.3"));
        assert_eq!(find_version(&deps, "b"), None);
        assert_eq!(find_paths(&deps, "a"), Some(vec![]));

        let _ = std::fs::remove_file(temp);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_dependencies_dispatches_by_filename() {
        let dir = unique_temp_dir("dispatch");
        let lock_path = dir.join("package-lock.json");
        let manifest_path = dir.join("package.json");
        std::fs::write(
            &lock_path,
            r#"{"dependencies":{"left-pad":{"version":"1.3.0"}}}"#,
        )
        .expect("write lock");
        std::fs::write(&manifest_path, r#"{"dependencies":{"chalk":"5.3.0"}}"#)
            .expect("write manifest");

        let parser = NpmLockfileParser::new();
        let lock_deps = parser.parse_dependencies(&lock_path).expect("parse lock");
        let manifest_deps = parser
            .parse_dependencies(&manifest_path)
            .expect("parse manifest");

        assert_eq!(find_version(&lock_deps, "left-pad"), Some("1.3.0"));
        assert_eq!(find_version(&manifest_deps, "chalk"), Some("5.3.0"));

        let _ = std::fs::remove_file(lock_path);
        let _ = std::fs::remove_file(manifest_path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_package_lock_captures_transitive_paths_from_dependencies_tree() {
        let dir = unique_temp_dir("deps-tree");
        let path = dir.join("package-lock.json");
        std::fs::write(
            &path,
            r#"{
              "name": "demo",
              "dependencies": {
                "react": {
                  "version": "18.2.0",
                  "dependencies": {
                    "loose-envify": {
                      "version": "1.4.0"
                    }
                  }
                }
              }
            }"#,
        )
        .expect("write lock");

        let deps = parse_package_lock(&path).expect("parse lock");
        assert_eq!(
            find_paths(&deps, "loose-envify"),
            Some(vec![vec!["react".to_string()]])
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_package_lock_uses_packages_fallback_when_dependencies_missing() {
        let dir = unique_temp_dir("packages-fallback");
        let path = dir.join("package-lock.json");
        std::fs::write(
            &path,
            r#"{
              "name": "demo",
              "packages": {
                "": { "name": "demo" },
                "node_modules/react": { "version": "18.2.0" },
                "node_modules/@types/node": { "version": "=20.11.0" },
                "node_modules/react/node_modules/loose-envify": { "version": "1.4.0" },
                "node_modules/invalid": { "version": "^1.0.0" }
              }
            }"#,
        )
        .expect("write lock");

        let deps = parse_package_lock(&path).expect("parse lock with packages");
        assert_eq!(deps.len(), 4);
        assert_eq!(find_version(&deps, "react"), Some("18.2.0"));
        assert_eq!(find_version(&deps, "@types/node"), Some("20.11.0"));
        assert_eq!(find_version(&deps, "invalid"), None);
        assert_eq!(find_paths(&deps, "react"), Some(vec![]));
        assert_eq!(
            find_paths(&deps, "loose-envify"),
            Some(vec![vec!["react".to_string()]])
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_package_lock_rejects_invalid_json() {
        let dir = unique_temp_dir("lock-invalid-json");
        let path = dir.join("package-lock.json");
        std::fs::write(&path, "{invalid").expect("write invalid json");

        let err = parse_package_lock(&path).expect_err("invalid json should fail");
        assert!(matches!(err, LockfileError::ParseFile { .. }));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_package_manifest_rejects_invalid_json() {
        let dir = unique_temp_dir("manifest-invalid-json");
        let path = dir.join("package.json");
        std::fs::write(&path, "{invalid").expect("write invalid json");

        let err = parse_package_manifest(&path).expect_err("invalid json should fail");
        assert!(matches!(err, LockfileError::ParseFile { .. }));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_npm_dependencies_rejects_unsupported_filename() {
        let dir = unique_temp_dir("unsupported");
        let path = dir.join("pnpm-lock.yaml");
        std::fs::write(&path, "lockfileVersion: 9").expect("write file");

        let err = parse_npm_dependencies(&path).expect_err("unsupported file");
        match err {
            LockfileError::UnsupportedFile {
                file_name,
                expected,
            } => {
                assert_eq!(file_name, "pnpm-lock.yaml");
                assert!(expected.contains("package-lock.json"));
                assert!(expected.contains("package.json"));
            }
            other => panic!("unexpected error variant: {other}"),
        }

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn extract_dependency_path_from_node_modules_path_handles_nested_scopes() {
        assert_eq!(
            extract_dependency_path_from_node_modules_path("node_modules/react"),
            Some(vec!["react".to_string()])
        );
        assert_eq!(
            extract_dependency_path_from_node_modules_path(
                "node_modules/react/node_modules/@scope/pkg"
            ),
            Some(vec!["react".to_string(), "@scope/pkg".to_string()])
        );
        assert_eq!(
            extract_dependency_path_from_node_modules_path("node_modules/"),
            None
        );
        assert_eq!(
            extract_dependency_path_from_node_modules_path("packages/demo"),
            None
        );
        assert_eq!(
            extract_dependency_path_from_node_modules_path("node_modules/../../evil"),
            None
        );
    }

    #[test]
    fn normalize_requested_version_only_keeps_exact_versions() {
        assert_eq!(normalize_requested_version(""), None);
        assert_eq!(
            normalize_requested_version(" latest "),
            Some("latest".to_string())
        );
        assert_eq!(
            normalize_requested_version("=1.2.3"),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            normalize_requested_version("1.2.3"),
            Some("1.2.3".to_string())
        );
        assert_eq!(normalize_requested_version("^1.2.3"), None);
    }

    #[test]
    fn normalize_npm_package_name_rejects_traversal_like_values() {
        assert_eq!(normalize_npm_package_name(""), None);
        assert_eq!(normalize_npm_package_name("../evil"), None);
        assert_eq!(normalize_npm_package_name(r"..\evil"), None);
        assert_eq!(normalize_npm_package_name("@scope/../evil"), None);
        assert_eq!(normalize_npm_package_name("pkg/sub"), None);
        assert_eq!(normalize_npm_package_name("@/pkg"), None);
        assert_eq!(normalize_npm_package_name("@scope/"), None);
    }

    #[test]
    fn normalize_npm_package_name_accepts_and_normalizes_valid_names() {
        assert_eq!(
            normalize_npm_package_name("@Scope/Package.Name"),
            Some("@scope/package.name".to_string())
        );
        assert_eq!(
            normalize_npm_package_name("React"),
            Some("react".to_string())
        );
    }

    #[test]
    fn parse_manifest_skips_invalid_dependency_names() {
        let dir = unique_temp_dir("invalid-names");
        let path = dir.join("package.json");
        std::fs::write(
            &path,
            r#"{
              "dependencies": {
                "good-pkg": "1.2.3",
                "../evil": "9.9.9",
                "@scope/pkg": "2.0.0"
              }
            }"#,
        )
        .expect("write manifest");

        let deps = parse_package_manifest(&path).expect("parse manifest");
        assert_eq!(deps.len(), 2);
        assert_eq!(find_version(&deps, "good-pkg"), Some("1.2.3"));
        assert_eq!(find_version(&deps, "@scope/pkg"), Some("2.0.0"));
        assert!(deps.iter().all(|spec| spec.name != "../evil"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }
}
