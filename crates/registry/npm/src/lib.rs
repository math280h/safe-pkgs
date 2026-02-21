mod lockfile;
mod registry;

use std::sync::Arc;

pub use lockfile::NpmLockfileParser;
pub use registry::NpmRegistryClient;
use safe_pkgs_core::{LockfileParser, RegistryClient, RegistryDefinition};

pub fn registry_definition() -> RegistryDefinition {
    RegistryDefinition {
        key: "npm",
        create_client,
        create_lockfile_parser: Some(create_lockfile_parser),
    }
}

fn create_client() -> Arc<dyn RegistryClient> {
    Arc::new(NpmRegistryClient::new())
}

fn create_lockfile_parser() -> Arc<dyn LockfileParser> {
    Arc::new(NpmLockfileParser::new())
}
