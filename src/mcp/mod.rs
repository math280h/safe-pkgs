//! MCP server module exports.

pub mod server;

/// MCP server entrypoint type used by CLI startup and tests.
pub use server::SafePkgsServer;
