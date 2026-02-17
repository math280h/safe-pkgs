#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod audit_log;
mod cache;
mod checks;
mod config;
mod mcp;
mod registries;
mod types;

use clap::{Parser, Subcommand};
use mcp::SafePkgsServer;
use rmcp::ServiceExt;

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
    /// Start the MCP server
    Serve {
        /// Run as MCP server over stdio
        #[arg(long)]
        mcp: bool,
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

            let server = SafePkgsServer::new()?;
            let service = server.serve(rmcp::transport::stdio()).await?;
            service.waiting().await?;
        }
        Commands::Audit { path } => {
            let server = SafePkgsServer::new()?;
            let report = server.audit_lockfile_path(&path).await?;
            let json = serde_json::to_string_pretty(&report)?;
            println!("{json}");
        }
    }

    Ok(())
}
