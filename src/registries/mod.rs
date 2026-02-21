//! Registry plugin catalog and support policy wiring.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};

pub use safe_pkgs_core::{
    CheckId, LockfileParser, RegistryClient, RegistryDefinition, RegistryPlugin, normalize_check_id,
};

/// Central check-support mode for a registry.
#[derive(Clone, Copy)]
pub enum RegistryCheckSupport {
    /// Registry supports all known checks.
    All,
    /// Registry supports all checks except the listed ids.
    AllExcept(&'static [CheckId]),
}

/// Runtime registry catalog built from app-registered definitions.
#[derive(Clone)]
pub struct RegistryCatalog {
    plugins_by_key: HashMap<&'static str, Arc<dyn RegistryPlugin>>,
    package_registry_keys: Vec<&'static str>,
    lockfile_registry_keys: Vec<&'static str>,
}

/// One row in the check-support matrix.
#[derive(Debug, Clone, Copy)]
pub struct CheckSupportRow {
    /// Registry key (for example `npm`).
    pub registry: &'static str,
    /// Check id.
    pub check: CheckId,
    /// Whether this check is supported for the registry.
    pub supported: bool,
}

impl RegistryCatalog {
    /// Returns the package-check plugin for a registry key.
    pub fn package_plugin(&self, key: &str) -> Option<&Arc<dyn RegistryPlugin>> {
        let normalized = key.to_ascii_lowercase();
        self.plugins_by_key.get(normalized.as_str())
    }

    /// Returns the lockfile-capable plugin for a registry key.
    pub fn lockfile_plugin(&self, key: &str) -> Option<&Arc<dyn RegistryPlugin>> {
        self.package_plugin(key)
            .filter(|plugin| plugin.lockfile_parser().is_some())
    }

    /// Ordered list of package registry keys.
    pub fn package_registry_keys(&self) -> &[&'static str] {
        &self.package_registry_keys
    }

    /// Ordered list of lockfile-enabled registry keys.
    pub fn lockfile_registry_keys(&self) -> &[&'static str] {
        &self.lockfile_registry_keys
    }

    /// Materializes a full support matrix for all known checks and registries.
    pub fn check_support_rows(&self) -> Vec<CheckSupportRow> {
        let known_checks = known_check_ids();
        registry_definitions()
            .iter()
            .flat_map(|def| {
                let support_mode = crate::app_registry_check_support(def.key);
                known_checks
                    .iter()
                    .copied()
                    .map(move |check| CheckSupportRow {
                        registry: def.key,
                        check,
                        supported: check_is_supported(support_mode, check),
                    })
            })
            .collect()
    }
}

/// Builds the default registry catalog from app-level definitions.
pub fn register_default_catalog() -> RegistryCatalog {
    let package_registry_keys = supported_package_registry_keys();
    let lockfile_registry_keys = supported_lockfile_registry_keys();

    let mut plugins_by_key = HashMap::new();
    let known_checks = known_check_ids();
    for def in registry_definitions() {
        let support_mode = crate::app_registry_check_support(def.key);
        let supported_checks = supported_checks(support_mode, &known_checks);
        let plugin = Arc::new(RegisteredPlugin {
            key: def.key,
            client: (def.create_client)(),
            supported_checks,
            lockfile_parser: def.create_lockfile_parser.map(|build| build()),
        }) as Arc<dyn RegistryPlugin>;
        plugins_by_key.insert(def.key, plugin);
    }

    RegistryCatalog {
        plugins_by_key,
        package_registry_keys,
        lockfile_registry_keys,
    }
}

/// Returns all package registry keys in registration order.
pub fn supported_package_registry_keys() -> Vec<&'static str> {
    registry_definitions().iter().map(|def| def.key).collect()
}

/// Returns all registries that provide a lockfile parser.
pub fn supported_lockfile_registry_keys() -> Vec<&'static str> {
    registry_definitions()
        .iter()
        .filter(|def| def.create_lockfile_parser.is_some())
        .map(|def| def.key)
        .collect()
}

/// Returns supported lockfile filenames for a registry key.
pub fn supported_lockfile_files_for_registry(key: &str) -> Option<Vec<&'static str>> {
    let catalog = register_default_catalog();
    let plugin = catalog.lockfile_plugin(key)?;
    let parser = plugin.lockfile_parser()?;
    Some(parser.supported_files().to_vec())
}

/// Validates lockfile registry + optional input path using shared parser metadata.
pub fn validate_lockfile_request(registry: &str, path: Option<&str>) -> Result<(), String> {
    let normalized_registry = registry.trim();
    if normalized_registry.is_empty() {
        return Err("registry must not be empty".to_string());
    }

    let Some(supported_files) = supported_lockfile_files_for_registry(normalized_registry) else {
        return Err(format!(
            "unsupported lockfile registry '{}'; supported registries: {}",
            normalized_registry,
            supported_lockfile_registry_keys().join(", ")
        ));
    };

    if let Some(raw_path) = path {
        let trimmed_path = raw_path.trim();
        if trimmed_path.is_empty() {
            return Err("path must not be an empty string".to_string());
        }

        let candidate = Path::new(trimmed_path);
        if candidate.exists() && candidate.is_file() {
            let Some(file_name) = candidate.file_name().and_then(|name| name.to_str()) else {
                return Err("path must refer to a regular dependency file".to_string());
            };
            if !supported_files.contains(&file_name) {
                return Err(format!(
                    "unsupported dependency file '{}'; expected one of: {}",
                    file_name,
                    supported_files.join(", ")
                ));
            }
        } else if candidate.exists() && !candidate.is_dir() {
            return Err("path must point to a regular file or directory".to_string());
        }
    }

    Ok(())
}

/// Returns the default package registry key.
pub fn default_package_registry_key() -> &'static str {
    registry_definitions()
        .first()
        .map(|def| def.key)
        .unwrap_or("npm")
}

/// Returns the default lockfile registry key.
pub fn default_lockfile_registry_key() -> &'static str {
    registry_definitions()
        .iter()
        .find(|def| def.create_lockfile_parser.is_some())
        .map(|def| def.key)
        .unwrap_or("npm")
}

#[derive(Clone)]
struct RegisteredPlugin {
    key: &'static str,
    client: Arc<dyn RegistryClient>,
    supported_checks: Vec<CheckId>,
    lockfile_parser: Option<Arc<dyn LockfileParser>>,
}

impl RegistryPlugin for RegisteredPlugin {
    fn key(&self) -> &'static str {
        self.key
    }

    fn client(&self) -> &dyn RegistryClient {
        self.client.as_ref()
    }

    fn supported_checks(&self) -> &[CheckId] {
        self.supported_checks.as_slice()
    }

    fn lockfile_parser(&self) -> Option<&dyn LockfileParser> {
        self.lockfile_parser.as_deref()
    }
}

fn registry_definitions() -> &'static [RegistryDefinition] {
    static DEFINITIONS: OnceLock<Vec<RegistryDefinition>> = OnceLock::new();
    DEFINITIONS
        .get_or_init(crate::app_registry_definitions)
        .as_slice()
}

fn known_check_ids() -> Vec<CheckId> {
    crate::checks::check_descriptors()
        .into_iter()
        .map(|descriptor| descriptor.id)
        .collect()
}

fn supported_checks(mode: RegistryCheckSupport, known_checks: &[CheckId]) -> Vec<CheckId> {
    known_checks
        .iter()
        .copied()
        .filter(|check| check_is_supported(mode, check))
        .collect()
}

fn check_is_supported(mode: RegistryCheckSupport, check: CheckId) -> bool {
    let normalized_check = normalize_check_id(check);
    match mode {
        RegistryCheckSupport::All => true,
        RegistryCheckSupport::AllExcept(disallowed) => !disallowed
            .iter()
            .any(|value| normalize_check_id(value) == normalized_check),
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
