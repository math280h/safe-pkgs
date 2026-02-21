use safe_pkgs_core::{DependencySpec, LockfileError, LockfileParser};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct PypiLockfileParser;

impl PypiLockfileParser {
    pub fn new() -> Self {
        Self
    }
}

impl LockfileParser for PypiLockfileParser {
    fn supported_files(&self) -> &'static [&'static str] {
        &["requirements.txt", "pyproject.toml"]
    }

    fn parse_dependencies(&self, path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
        parse_pypi_dependencies(path)
    }
}

fn parse_pypi_dependencies(path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(LockfileError::InvalidInputPath {
            path: path.display().to_string(),
        });
    };

    match file_name {
        "requirements.txt" => parse_requirements_file(path),
        "pyproject.toml" => parse_pyproject_manifest(path),
        _ => Err(LockfileError::UnsupportedFile {
            file_name: file_name.to_string(),
            expected: "requirements.txt, pyproject.toml".to_string(),
        }),
    }
}

fn parse_requirements_file(path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
    let raw = std::fs::read_to_string(path).map_err(|source| LockfileError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    let mut dependencies = BTreeMap::<String, Option<String>>::new();

    for line in raw.lines() {
        if let Some(spec) = parse_python_requirement_line(line) {
            insert_dependency_spec(&mut dependencies, spec);
        }
    }

    Ok(dependencies
        .into_iter()
        .map(|(name, version)| DependencySpec { name, version })
        .collect())
}

fn parse_pyproject_manifest(path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
    let raw = std::fs::read_to_string(path).map_err(|source| LockfileError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    let root: toml::Value = toml::from_str(&raw).map_err(|error| LockfileError::ParseFile {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    let mut dependencies = BTreeMap::<String, Option<String>>::new();

    if let Some(project_deps) = root
        .get("project")
        .and_then(|value| value.get("dependencies"))
        .and_then(|value| value.as_array())
    {
        for item in project_deps {
            let Some(raw_requirement) = item.as_str() else {
                continue;
            };
            if let Some(spec) = parse_python_requirement_line(raw_requirement) {
                insert_dependency_spec(&mut dependencies, spec);
            }
        }
    }

    if let Some(optional_deps) = root
        .get("project")
        .and_then(|value| value.get("optional-dependencies"))
        .and_then(|value| value.as_table())
    {
        for group_values in optional_deps.values() {
            let Some(items) = group_values.as_array() else {
                continue;
            };
            for item in items {
                let Some(raw_requirement) = item.as_str() else {
                    continue;
                };
                if let Some(spec) = parse_python_requirement_line(raw_requirement) {
                    insert_dependency_spec(&mut dependencies, spec);
                }
            }
        }
    }

    if let Some(poetry_deps) = root
        .get("tool")
        .and_then(|value| value.get("poetry"))
        .and_then(|value| value.get("dependencies"))
        .and_then(|value| value.as_table())
    {
        parse_poetry_dependencies_table(poetry_deps, &mut dependencies);
    }

    if let Some(poetry_groups) = root
        .get("tool")
        .and_then(|value| value.get("poetry"))
        .and_then(|value| value.get("group"))
        .and_then(|value| value.as_table())
    {
        for group in poetry_groups.values() {
            let Some(group_deps) = group.get("dependencies").and_then(|value| value.as_table())
            else {
                continue;
            };
            parse_poetry_dependencies_table(group_deps, &mut dependencies);
        }
    }

    Ok(dependencies
        .into_iter()
        .map(|(name, version)| DependencySpec { name, version })
        .collect())
}

fn parse_poetry_dependencies_table(
    table: &toml::value::Table,
    dependencies: &mut BTreeMap<String, Option<String>>,
) {
    for (name, value) in table {
        if name.eq_ignore_ascii_case("python") {
            continue;
        }

        let Some(normalized_name) = normalize_python_package_name(name) else {
            continue;
        };

        let version = match value {
            toml::Value::String(raw) => normalize_poetry_exact_version(raw),
            toml::Value::Table(entries) => entries
                .get("version")
                .and_then(|version| version.as_str())
                .and_then(normalize_poetry_exact_version),
            _ => None,
        };

        insert_dependency_spec(
            dependencies,
            DependencySpec {
                name: normalized_name,
                version,
            },
        );
    }
}

fn parse_python_requirement_line(line: &str) -> Option<DependencySpec> {
    let mut candidate = line.trim();
    if candidate.is_empty() || candidate.starts_with('#') {
        return None;
    }

    if let Some((before_marker, _)) = candidate.split_once(';') {
        candidate = before_marker.trim();
    }

    if let Some(comment_index) = candidate.find('#') {
        candidate = candidate[..comment_index].trim();
    }

    if candidate.is_empty() || candidate.starts_with('-') {
        return None;
    }

    if let Some((name_part, _)) = candidate.split_once(" @ ") {
        let name = normalize_python_package_name(name_part)?;
        return Some(DependencySpec {
            name,
            version: None,
        });
    }

    for operator in ["===", "==", "~=", ">=", "<=", "!=", "<", ">"] {
        if let Some(index) = candidate.find(operator) {
            let name = normalize_python_package_name(candidate[..index].trim())?;
            let version = if operator == "==" || operator == "===" {
                normalize_python_exact_version(candidate[index + operator.len()..].trim())
            } else {
                None
            };
            return Some(DependencySpec { name, version });
        }
    }

    let name = normalize_python_package_name(candidate)?;
    Some(DependencySpec {
        name,
        version: None,
    })
}

fn normalize_python_package_name(raw: &str) -> Option<String> {
    let without_extras = raw.split_once('[').map_or(raw, |(name, _)| name);
    let trimmed = without_extras.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.contains('/') || trimmed.contains('\\') {
        return None;
    }

    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return None;
    }

    // Normalize per PEP 503: lowercase and collapse runs of [-_.] into '-'.
    let mut normalized = String::with_capacity(trimmed.len());
    let mut previous_was_separator = false;
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            previous_was_separator = false;
        } else if !previous_was_separator {
            normalized.push('-');
            previous_was_separator = true;
        }
    }

    let normalized = normalized.trim_matches('-').to_string();
    if normalized.is_empty() {
        return None;
    }

    Some(normalized)
}

fn normalize_python_exact_version(raw: &str) -> Option<String> {
    let candidate = raw.split(',').next().unwrap_or(raw).trim();
    if candidate.is_empty() {
        return None;
    }

    if candidate.contains('*')
        || candidate.contains(' ')
        || candidate.contains(';')
        || candidate.contains('<')
        || candidate.contains('>')
        || candidate.contains('~')
        || candidate.contains('!')
        || candidate.contains('^')
    {
        return None;
    }

    Some(candidate.to_string())
}

fn normalize_poetry_exact_version(raw: &str) -> Option<String> {
    let candidate = raw.trim();
    if candidate.is_empty() || candidate == "*" {
        return None;
    }

    if let Some(version) = candidate.strip_prefix("==") {
        return normalize_python_exact_version(version);
    }

    if let Some(version) = candidate.strip_prefix('=') {
        return normalize_python_exact_version(version);
    }

    if candidate.contains(',')
        || candidate.contains('|')
        || candidate.contains('<')
        || candidate.contains('>')
        || candidate.contains('~')
        || candidate.contains('!')
        || candidate.contains('^')
        || candidate.contains('*')
    {
        return None;
    }

    Some(candidate.to_string())
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
        let dir = std::env::temp_dir().join(format!("safe-pkgs-pypi-lockfile-{nanos}-{suffix}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn find_version<'a>(deps: &'a [DependencySpec], name: &str) -> Option<&'a str> {
        deps.iter()
            .find(|spec| spec.name == name)
            .and_then(|spec| spec.version.as_deref())
    }

    #[test]
    fn parse_requirements_file_supports_exact_pins() {
        let dir = unique_temp_dir("requirements");
        let temp = dir.join("requirements.txt");
        std::fs::write(
            &temp,
            "requests==2.31.0\nurllib3>=2.0\nrich[markdown]==13.7.1\n# comment\n-r other.txt\n",
        )
        .expect("write requirements");

        let deps = parse_requirements_file(&temp).expect("parse requirements");
        assert_eq!(deps.len(), 3);
        assert_eq!(find_version(&deps, "requests"), Some("2.31.0"));
        assert_eq!(find_version(&deps, "rich"), Some("13.7.1"));
        assert_eq!(find_version(&deps, "urllib3"), None);

        let _ = std::fs::remove_file(temp);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_dependencies_dispatches_by_filename() {
        let parser = PypiLockfileParser::new();
        let req_dir = unique_temp_dir("dispatch-req");
        let req_path = req_dir.join("requirements.txt");
        std::fs::write(&req_path, "fastapi==0.111.0").expect("write requirements");

        let py_dir = unique_temp_dir("dispatch-pyproject");
        let py_path = py_dir.join("pyproject.toml");
        std::fs::write(
            &py_path,
            r#"
[project]
dependencies = ["httpx==0.27.0"]
"#,
        )
        .expect("write pyproject");

        let req = parser
            .parse_dependencies(&req_path)
            .expect("parse requirements");
        let py = parser
            .parse_dependencies(&py_path)
            .expect("parse pyproject");
        assert_eq!(find_version(&req, "fastapi"), Some("0.111.0"));
        assert_eq!(find_version(&py, "httpx"), Some("0.27.0"));

        let _ = std::fs::remove_file(req_path);
        let _ = std::fs::remove_file(py_path);
        let _ = std::fs::remove_dir_all(req_dir);
        let _ = std::fs::remove_dir_all(py_dir);
    }

    #[test]
    fn parse_pypi_dependencies_rejects_unsupported_filename() {
        let dir = unique_temp_dir("unsupported");
        let path = dir.join("poetry.lock");
        std::fs::write(&path, "[]").expect("write lock");

        let err = parse_pypi_dependencies(&path).expect_err("unsupported file");
        assert!(matches!(err, LockfileError::UnsupportedFile { .. }));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_pyproject_manifest_reads_project_and_poetry_sections() {
        let dir = unique_temp_dir("pyproject");
        let path = dir.join("pyproject.toml");
        std::fs::write(
            &path,
            r#"
[project]
dependencies = [
  "requests==2.31.0",
  "urllib3>=2.0"
]

[project.optional-dependencies]
dev = ["pytest==8.2.0", "ruff>=0.5.0"]

[tool.poetry.dependencies]
python = "^3.11"
httpx = "==0.27.0"
rich = { version = "=13.7.1" }
click = "^8.0"

[tool.poetry.group.docs.dependencies]
mkdocs = "1.6.0"
"#,
        )
        .expect("write pyproject");

        let deps = parse_pyproject_manifest(&path).expect("parse pyproject");
        assert_eq!(find_version(&deps, "requests"), Some("2.31.0"));
        assert_eq!(find_version(&deps, "urllib3"), None);
        assert_eq!(find_version(&deps, "pytest"), Some("8.2.0"));
        assert_eq!(find_version(&deps, "httpx"), Some("0.27.0"));
        assert_eq!(find_version(&deps, "rich"), Some("13.7.1"));
        assert_eq!(find_version(&deps, "click"), None);
        assert_eq!(find_version(&deps, "mkdocs"), Some("1.6.0"));
        assert!(deps.iter().all(|dep| dep.name != "python"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_pyproject_manifest_rejects_invalid_toml() {
        let dir = unique_temp_dir("invalid-toml");
        let path = dir.join("pyproject.toml");
        std::fs::write(&path, "[project\nname =").expect("write invalid toml");

        let err = parse_pyproject_manifest(&path).expect_err("invalid toml should fail");
        assert!(matches!(err, LockfileError::ParseFile { .. }));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_python_requirement_line_supports_common_forms() {
        let pinned = parse_python_requirement_line("requests==2.31.0").expect("pinned dep");
        assert_eq!(pinned.name, "requests");
        assert_eq!(pinned.version.as_deref(), Some("2.31.0"));

        let dotted = parse_python_requirement_line("zope.interface==6.4.0").expect("dotted dep");
        assert_eq!(dotted.name, "zope-interface");
        assert_eq!(dotted.version.as_deref(), Some("6.4.0"));

        let ranged = parse_python_requirement_line("urllib3>=2.0").expect("ranged dep");
        assert_eq!(ranged.name, "urllib3");
        assert!(ranged.version.is_none());

        let direct =
            parse_python_requirement_line("demo @ https://example.com/demo.whl").expect("direct");
        assert_eq!(direct.name, "demo");
        assert!(direct.version.is_none());

        assert!(parse_python_requirement_line("# comment").is_none());
        assert!(parse_python_requirement_line("-r other.txt").is_none());
    }

    #[test]
    fn normalize_helpers_reject_invalid_data() {
        assert_eq!(
            normalize_python_package_name("rich[markdown]"),
            Some("rich".to_string())
        );
        assert_eq!(
            normalize_python_package_name("Zope.Interface"),
            Some("zope-interface".to_string())
        );
        assert_eq!(
            normalize_python_package_name("my_pkg-name"),
            Some("my-pkg-name".to_string())
        );
        assert_eq!(normalize_python_package_name(""), None);
        assert_eq!(
            normalize_python_package_name("bad.name"),
            Some("bad-name".to_string())
        );
        assert_eq!(normalize_python_package_name("../evil"), None);
        assert_eq!(normalize_python_package_name(r"..\evil"), None);
        assert_eq!(normalize_python_package_name("..."), None);

        assert_eq!(
            normalize_python_exact_version("2.31.0,>=2"),
            Some("2.31.0".to_string())
        );
        assert_eq!(normalize_python_exact_version("2.*"), None);

        assert_eq!(
            normalize_poetry_exact_version("==1.2.3"),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            normalize_poetry_exact_version("1.2.3"),
            Some("1.2.3".to_string())
        );
        assert_eq!(normalize_poetry_exact_version("^1.2"), None);
        assert_eq!(normalize_poetry_exact_version("*"), None);
    }

    #[test]
    fn insert_dependency_spec_prefers_exact_pin_over_unpinned() {
        let mut deps = BTreeMap::<String, Option<String>>::new();
        insert_dependency_spec(
            &mut deps,
            DependencySpec {
                name: "demo".to_string(),
                version: None,
            },
        );
        insert_dependency_spec(
            &mut deps,
            DependencySpec {
                name: "demo".to_string(),
                version: Some("1.0.0".to_string()),
            },
        );
        insert_dependency_spec(
            &mut deps,
            DependencySpec {
                name: "demo".to_string(),
                version: None,
            },
        );
        assert_eq!(deps.get("demo"), Some(&Some("1.0.0".to_string())));
    }
}
