mod lockfile;
mod registry;

use std::sync::Arc;

pub use lockfile::CargoLockfileParser;
pub use registry::CargoRegistryClient;
use safe_pkgs_core::{LockfileParser, RegistryClient, RegistryDefinition};

pub fn registry_definition() -> RegistryDefinition {
    RegistryDefinition {
        key: "cargo",
        create_client,
        create_lockfile_parser: Some(create_lockfile_parser),
    }
}

fn create_client() -> Arc<dyn RegistryClient> {
    Arc::new(CargoRegistryClient::new())
}

fn create_lockfile_parser() -> Arc<dyn LockfileParser> {
    Arc::new(CargoLockfileParser::new())
}
