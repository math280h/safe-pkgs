use crate::checks::CheckFinding;
use crate::registries::PackageVersion;
use crate::types::Severity;

const SUSPICIOUS_PATTERNS: [&str; 11] = [
    "curl ",
    "wget ",
    "http://",
    "https://",
    "invoke-webrequest",
    "powershell",
    "base64",
    "eval(",
    "bash -c",
    "sh -c",
    "certutil",
];

pub async fn run(package_name: &str, version: &PackageVersion) -> Option<CheckFinding> {
    if version.install_scripts.is_empty() {
        return None;
    }

    let suspicious = version
        .install_scripts
        .iter()
        .find(|script| is_suspicious(script));

    suspicious.map(|script| CheckFinding {
        severity: Severity::High,
        reason: format!(
            "{package_name}@{} has a suspicious install hook: {script}",
            version.version
        ),
    })
}

fn is_suspicious(script: &str) -> bool {
    let normalized = script.to_ascii_lowercase();
    SUSPICIOUS_PATTERNS
        .iter()
        .any(|pattern| normalized.contains(pattern))
}

#[cfg(test)]
#[path = "install_script_tests.rs"]
mod tests;
