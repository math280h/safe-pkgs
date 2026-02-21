//! MCP tool handlers and request/response orchestration.

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler, handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters, model::*, tool, tool_handler, tool_router,
};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::Deserialize;

use crate::service::SafePkgsService;

fn default_package_registry() -> String {
    crate::registries::default_package_registry_key().to_string()
}

fn package_registry_schema(generator: &mut SchemaGenerator) -> Schema {
    let mut schema = String::json_schema(generator);
    schema.insert(
        "enum".into(),
        serde_json::json!(crate::registries::supported_package_registry_keys()),
    );
    schema.insert(
        "default".into(),
        serde_json::json!(crate::registries::default_package_registry_key()),
    );
    schema
}

fn lockfile_registry_schema(generator: &mut SchemaGenerator) -> Schema {
    let mut schema = String::json_schema(generator);
    schema.insert(
        "enum".into(),
        serde_json::json!(crate::registries::supported_lockfile_registry_keys()),
    );
    schema.insert(
        "default".into(),
        serde_json::json!(crate::registries::default_lockfile_registry_key()),
    );
    schema
}

fn default_lockfile_registry() -> String {
    crate::registries::default_lockfile_registry_key().to_string()
}

/// Parameters for the `check_package` MCP tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PackageQuery {
    #[schemars(description = "Package name, e.g. \"lodash\"")]
    /// Package name to evaluate.
    pub name: String,

    #[schemars(description = "Specific version or \"latest\". Defaults to \"latest\" if omitted.")]
    /// Optional version. Uses latest when omitted.
    pub version: Option<String>,

    #[schemars(
        description = "Package registry. Defaults to \"npm\". Supported: \"npm\", \"cargo\", \"pypi\"."
    )]
    #[serde(default = "default_package_registry")]
    #[schemars(schema_with = "package_registry_schema")]
    /// Registry key (`npm`, `cargo`, `pypi`).
    pub registry: String,
}

/// Parameters for the `check_lockfile` MCP tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LockfileQuery {
    #[schemars(
        description = "Path to a dependency file or project directory. npm accepts package-lock.json/package.json. cargo accepts Cargo.lock/Cargo.toml. pypi accepts requirements.txt/pyproject.toml. Defaults to current working directory."
    )]
    /// Path to a lockfile/manifest file or project directory.
    pub path: Option<String>,

    #[schemars(
        description = "Registry for dependency checks. Defaults to npm. Supports npm, cargo, and pypi lockfile/manifest parsing."
    )]
    #[serde(default = "default_lockfile_registry")]
    #[schemars(schema_with = "lockfile_registry_schema")]
    /// Registry key used for parser + checks.
    pub registry: String,
}

/// MCP transport adapter for the shared package safety service.
#[derive(Clone)]
pub struct SafePkgsServer {
    tool_router: ToolRouter<Self>,
    service: Arc<SafePkgsService>,
}

#[tool_router]
impl SafePkgsServer {
    /// Creates a server using the default runtime service.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying service fails to initialize.
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self::with_service(SafePkgsService::new()?))
    }

    #[cfg(test)]
    /// Creates a test server using a test-configured runtime service.
    pub fn with_config(config: crate::config::SafePkgsConfig) -> Self {
        Self::with_service(SafePkgsService::with_config(config))
    }

    fn with_service(service: SafePkgsService) -> Self {
        Self {
            tool_router: Self::tool_router(),
            service: Arc::new(service),
        }
    }

    #[tool(
        name = "check_package",
        description = "Check whether a package is safe to install from a supported registry (npm, cargo, pypi). Call this before package installation. Returns allow/deny, a risk level, and human-readable reasons."
    )]
    async fn check_package(
        &self,
        Parameters(query): Parameters<PackageQuery>,
    ) -> Result<CallToolResult, McpError> {
        validate_package_query(&query)?;

        let response = self
            .service
            .evaluate_package(
                &query.name,
                query.version.as_deref(),
                &query.registry,
                "check_package",
            )
            .await
            .map_err(mcp_internal_error)?;

        let json = serde_json::to_string_pretty(&response).map_err(mcp_internal_error)?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        name = "check_lockfile",
        description = "Batch-check dependencies from supported lockfile/manifest formats. npm: package-lock.json/package.json. cargo: Cargo.lock/Cargo.toml. pypi: requirements.txt/pyproject.toml. Returns aggregate allow/risk and per-package findings."
    )]
    async fn check_lockfile(
        &self,
        Parameters(query): Parameters<LockfileQuery>,
    ) -> Result<CallToolResult, McpError> {
        validate_lockfile_query(&query)?;

        let response = self
            .service
            .run_lockfile_audit(query.path.as_deref(), &query.registry, "check_lockfile")
            .await
            .map_err(mcp_internal_error)?;

        let json = serde_json::to_string_pretty(&response).map_err(mcp_internal_error)?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

#[tool_handler]
impl ServerHandler for SafePkgsServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Package safety checker for supported registries (npm, cargo, pypi). Call check_package before package installation or check_lockfile for batch dependency review.".into(),
            ),
        }
    }
}

fn mcp_internal_error(error: impl ToString) -> McpError {
    McpError::internal_error(error.to_string(), None)
}

fn validate_package_query(query: &PackageQuery) -> Result<(), McpError> {
    if query.name.trim().is_empty() {
        return Err(McpError::invalid_params(
            "package name must not be empty",
            None,
        ));
    }
    if query.registry.trim().is_empty() {
        return Err(McpError::invalid_params("registry must not be empty", None));
    }
    if let Some(version) = query.version.as_deref()
        && version.trim().is_empty()
    {
        return Err(McpError::invalid_params(
            "version must not be an empty string",
            None,
        ));
    }
    Ok(())
}

fn validate_lockfile_query(query: &LockfileQuery) -> Result<(), McpError> {
    crate::registries::validate_lockfile_request(&query.registry, query.path.as_deref())
        .map_err(|message| McpError::invalid_params(message, None))
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
