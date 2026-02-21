mod audit_log;
mod cache;
mod checks;
mod config;
mod mcp;
mod registries;
mod types;

use clap::{Parser, Subcommand};
use mcp::{PackageRegistry, SafePkgsServer};
use rmcp::ServiceExt;

#[derive(Parser)]
#[command(
    name = "safe-pkgs",
    version,
    about = "MCP server for safe package installation"
)]
struct Cli {
    /// HTTPS/HTTP proxy URL (for example: http://127.0.0.1:3128)
    #[arg(long, global = true)]
    https_proxy: Option<String>,

    /// Path to a PEM certificate file to trust for outbound TLS (for corporate MITM/SSL inspection)
    #[arg(long, global = true)]
    ca_cert: Option<String>,

    /// Disable TLS certificate verification (debugging only; unsafe)
    #[arg(long, global = true)]
    insecure_skip_tls_verify: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum CliRegistry {
    Npm,
    Cargo,
}

impl From<CliRegistry> for PackageRegistry {
    fn from(value: CliRegistry) -> Self {
        match value {
            CliRegistry::Npm => PackageRegistry::Npm,
            CliRegistry::Cargo => PackageRegistry::Cargo,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MCP server
    Serve {
        /// Run as MCP server over stdio
        #[arg(long)]
        mcp: bool,
    },
    /// Check a single package directly (same decision shape as MCP check_package)
    #[command(name = "check", alias = "check-package")]
    Check {
        /// Package name or package spec (for example: lodash, lodash@4.17.21, @types/node, @types/node@20.11.0)
        package: String,
        /// Optional explicit version (for example: 4.17.21). If omitted, latest is checked.
        version: Option<String>,
        /// Package registry
        #[arg(long, value_enum, default_value_t = CliRegistry::Npm)]
        registry: CliRegistry,
    },
    /// Run a one-off dependency audit from package-lock.json or package.json
    Audit {
        /// Path to package-lock.json/package.json or project directory
        path: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let server = build_server(
        cli.https_proxy.as_deref(),
        cli.ca_cert.as_deref(),
        cli.insecure_skip_tls_verify,
    )?;

    match cli.command {
        Commands::Serve { mcp } => {
            if !mcp {
                anyhow::bail!("Only --mcp mode is currently supported");
            }

            // MCP over stdio — logs must go to stderr, stdout is the transport
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .init();

            tracing::info!("safe-pkgs MCP server starting");

            let service = server.serve(rmcp::transport::stdio()).await?;
            service.waiting().await?;
        }
        Commands::Check {
            package,
            version,
            registry,
        } => {
            let (name, resolved_version) =
                normalize_cli_package_input(&package, version.as_deref())?;
            let response = server
                .check_package_cli(&name, resolved_version.as_deref(), registry.into())
                .await?;
            let json = serde_json::to_string_pretty(&response)?;
            println!("{json}");
        }
        Commands::Audit { path } => {
            let report = server.audit_lockfile_path(&path).await?;
            let json = serde_json::to_string_pretty(&report)?;
            println!("{json}");
        }
    }

    Ok(())
}

fn build_server(
    https_proxy: Option<&str>,
    ca_cert: Option<&str>,
    insecure_skip_tls_verify: bool,
) -> anyhow::Result<SafePkgsServer> {
    let proxy_url = https_proxy.map(str::trim).filter(|value| !value.is_empty());
    let ca_cert_path = ca_cert.map(str::trim).filter(|value| !value.is_empty());

    if proxy_url.is_none() && ca_cert_path.is_none() && !insecure_skip_tls_verify {
        return SafePkgsServer::new();
    }

    let mut builder = reqwest::Client::builder();

    if let Some(proxy_url) = proxy_url {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|err| anyhow::anyhow!("invalid --https-proxy value '{proxy_url}': {err}"))?;
        builder = builder.proxy(proxy);
    }

    if let Some(ca_cert_path) = ca_cert_path {
        let cert_bytes = std::fs::read(ca_cert_path).map_err(|err| {
            anyhow::anyhow!("failed to read --ca-cert file '{ca_cert_path}': {err}")
        })?;
        let cert = reqwest::Certificate::from_pem(&cert_bytes).map_err(|err| {
            anyhow::anyhow!("failed to parse PEM certificate from '{ca_cert_path}': {err}")
        })?;
        builder = builder.add_root_certificate(cert);
    }

    if insecure_skip_tls_verify {
        builder = builder.danger_accept_invalid_certs(true);
    }

    let http_client = builder.build().map_err(|err| {
        anyhow::anyhow!("failed to build HTTP client with custom network settings: {err}")
    })?;

    SafePkgsServer::new_with_http_client(http_client)
}

fn normalize_cli_package_input(
    raw_package: &str,
    explicit_version: Option<&str>,
) -> anyhow::Result<(String, Option<String>)> {
    let package = raw_package.trim();
    if package.is_empty() {
        anyhow::bail!("package name cannot be empty");
    }

    let (parsed_name, inline_version) = parse_inline_package_version(package)?;
    let version = match (
        inline_version,
        explicit_version
            .map(str::trim)
            .filter(|value| !value.is_empty()),
    ) {
        (Some(inline), Some(explicit)) if inline != explicit => {
            anyhow::bail!(
                "conflicting versions provided: inline '{inline}' does not match explicit '{explicit}'"
            );
        }
        (Some(inline), _) => Some(inline),
        (None, Some(explicit)) => Some(explicit.to_string()),
        (None, None) => None,
    };

    Ok((parsed_name, version))
}

fn parse_inline_package_version(package: &str) -> anyhow::Result<(String, Option<String>)> {
    if package.ends_with('@') {
        anyhow::bail!("invalid package spec '{package}': version after '@' is empty");
    }

    let Some((name, version)) = package.rsplit_once('@') else {
        return Ok((package.to_string(), None));
    };

    // Scoped package names like @types/node have a leading '@' but no inline version.
    if name.is_empty() {
        return Ok((package.to_string(), None));
    }

    Ok((name.to_string(), Some(version.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_without_version_is_accepted() {
        let (name, version) =
            normalize_cli_package_input("lodash", None).expect("normalize package");
        assert_eq!(name, "lodash");
        assert_eq!(version, None);
    }

    #[test]
    fn package_with_inline_version_is_accepted() {
        let (name, version) =
            normalize_cli_package_input("lodash@4.17.21", None).expect("normalize package");
        assert_eq!(name, "lodash");
        assert_eq!(version.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn scoped_package_without_inline_version_is_accepted() {
        let (name, version) =
            normalize_cli_package_input("@types/node", None).expect("normalize package");
        assert_eq!(name, "@types/node");
        assert_eq!(version, None);
    }

    #[test]
    fn scoped_package_with_inline_version_is_accepted() {
        let (name, version) =
            normalize_cli_package_input("@types/node@20.11.0", None).expect("normalize package");
        assert_eq!(name, "@types/node");
        assert_eq!(version.as_deref(), Some("20.11.0"));
    }

    #[test]
    fn conflicting_inline_and_explicit_versions_are_rejected() {
        let err = normalize_cli_package_input("lodash@4.17.21", Some("4.17.20"))
            .expect_err("conflict should fail");
        assert!(
            err.to_string()
                .contains("conflicting versions provided: inline")
        );
    }

    #[test]
    fn trailing_at_symbol_is_rejected() {
        let err = normalize_cli_package_input("lodash@", None).expect_err("should fail");
        assert!(err.to_string().contains("version after '@' is empty"));
    }
}
