#![cfg_attr(windows, windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::{Command, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn main() -> anyhow::Result<()> {
    let server_binary = resolve_server_binary();
    let forwarded_args = std::env::args().skip(1).collect::<Vec<_>>();
    let args = if forwarded_args.is_empty() {
        vec!["serve".to_string(), "--mcp".to_string()]
    } else {
        forwarded_args
    };

    let mut command = Command::new(server_binary);
    command
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let status = command.status()?;
    std::process::exit(status.code().unwrap_or(1));
}

fn resolve_server_binary() -> PathBuf {
    let current = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let sibling = current.with_file_name(server_binary_name());
    if sibling.exists() {
        return sibling;
    }
    PathBuf::from(server_binary_name())
}

#[cfg(windows)]
fn server_binary_name() -> &'static str {
    "safe-pkgs.exe"
}

#[cfg(not(windows))]
fn server_binary_name() -> &'static str {
    "safe-pkgs"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_binary_name_matches_platform() {
        #[cfg(windows)]
        assert_eq!(server_binary_name(), "safe-pkgs.exe");
        #[cfg(not(windows))]
        assert_eq!(server_binary_name(), "safe-pkgs");
    }

    #[test]
    fn resolve_server_binary_points_to_expected_filename() {
        let resolved = resolve_server_binary();
        let name = resolved
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        assert_eq!(name, server_binary_name());
    }
}
