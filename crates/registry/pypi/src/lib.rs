mod lockfile;
mod registry;

use std::sync::Arc;

pub use lockfile::PypiLockfileParser;
pub use registry::PypiRegistryClient;
use safe_pkgs_core::{LockfileParser, RegistryClient, RegistryDefinition};

pub fn registry_definition() -> RegistryDefinition {
    RegistryDefinition {
        key: "pypi",
        create_client,
        create_lockfile_parser: Some(create_lockfile_parser),
    }
}

fn create_client() -> Arc<dyn RegistryClient> {
    Arc::new(PypiRegistryClient::new())
}

fn create_lockfile_parser() -> Arc<dyn LockfileParser> {
    Arc::new(PypiLockfileParser::new())
}
