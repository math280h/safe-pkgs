//! CLI entrypoint for serving MCP tools and running lockfile audits.

mod audit_log;
mod cache;
mod checks;
mod config;
mod custom_rules;
mod mcp;
mod policy_snapshot;
mod registries;
mod service;
mod support_map;
mod types;

use clap::{Parser, Subcommand};
use mcp::SafePkgsServer;
use rmcp::ServiceExt;
use service::SafePkgsService;
use std::io::IsTerminal;

#[cfg(windows)]
fn hide_console_window() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetConsoleWindow() -> *mut core::ffi::c_void;
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn ShowWindow(window: *mut core::ffi::c_void, show_cmd: i32) -> i32;
    }

    const SW_HIDE: i32 = 0;
    unsafe {
        let window = GetConsoleWindow();
        if !window.is_null() {
            let _ = ShowWindow(window, SW_HIDE);
        }
    }
}

#[cfg(not(windows))]
fn hide_console_window() {}

#[derive(Parser)]
#[command(
    name = "safe-pkgs",
    version,
    about = "MCP server for safe package installation"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MCP server over stdio
    #[cfg_attr(windows, command(hide = true))]
    Serve,
    /// Run a one-off dependency audit from supported lockfile/manifest formats
    Audit {
        /// Path to a dependency file or project directory
        path: String,
        /// Registry for dependency file parsing and package checks
        #[arg(long, default_value_t = crate::registries::default_lockfile_registry_key().to_string())]
        registry: String,
    },
    /// Print check support for registries
    SupportMap {
        /// Disable ANSI colors
        #[arg(long)]
        no_color: bool,
    },
}

/// Returns registry definitions wired into this application build.
pub(crate) fn app_registry_definitions() -> Vec<registries::RegistryDefinition> {
    vec![
        safe_pkgs_npm::registry_definition(),
        safe_pkgs_cargo::registry_definition(),
        safe_pkgs_pypi::registry_definition(),
    ]
}

/// Returns check factories wired into this application build.
pub(crate) fn app_check_factories() -> Vec<safe_pkgs_core::CheckFactory> {
    vec![
        safe_pkgs_check_existence::create_check,
        safe_pkgs_check_version_age::create_check,
        safe_pkgs_check_staleness::create_check,
        safe_pkgs_check_popularity::create_check,
        safe_pkgs_check_install_script::create_check,
        safe_pkgs_check_typosquat::create_check,
        safe_pkgs_check_advisory::create_check,
    ]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve => {
            hide_console_window();

            // MCP over stdio — logs must go to stderr, stdout is the transport
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .init();

            tracing::info!("safe-pkgs MCP server starting");

            let server = SafePkgsServer::new()?;
            let service = server.serve(rmcp::transport::stdio()).await?;
            service.waiting().await?;
        }
        Commands::Audit { path, registry } => {
            let service = SafePkgsService::new()?;
            let report = service
                .audit_lockfile_path_with_registry(&path, &registry)
                .await?;
            let json = serde_json::to_string_pretty(&report)?;
            println!("{json}");
        }
        Commands::SupportMap { no_color } => {
            let use_color = !no_color
                && std::io::stdout().is_terminal()
                && std::env::var_os("NO_COLOR").is_none();
            println!("{}", support_map::render_support_map(use_color));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_registry_definitions_include_expected_keys() {
        let defs = app_registry_definitions();
        let keys = defs.iter().map(|def| def.key).collect::<Vec<_>>();
        assert!(keys.contains(&"npm"));
        assert!(keys.contains(&"cargo"));
        assert!(keys.contains(&"pypi"));
    }

    #[test]
    fn registry_definitions_excluded_checks_are_correct() {
        let defs = app_registry_definitions();
        let npm = defs.iter().find(|d| d.key == "npm").expect("npm definition");
        let cargo = defs.iter().find(|d| d.key == "cargo").expect("cargo definition");
        let pypi = defs.iter().find(|d| d.key == "pypi").expect("pypi definition");

        assert!(npm.excluded_checks.is_empty());
        assert!(cargo.excluded_checks.contains(&"install_script"));
        assert!(pypi.excluded_checks.contains(&"install_script"));
    }

    #[test]
    fn app_check_factories_register_core_checks() {
        let checks = app_check_factories();
        assert!(checks.len() >= 7);
        let ids = checks
            .into_iter()
            .map(|factory| factory().id())
            .collect::<Vec<_>>();
        assert!(ids.contains(&"existence"));
        assert!(ids.contains(&"version_age"));
        assert!(ids.contains(&"advisory"));
    }
}
