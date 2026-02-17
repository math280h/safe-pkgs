use crate::checks::CheckFinding;
use crate::types::Severity;

pub fn missing_package(package_name: &str) -> CheckFinding {
    CheckFinding {
        severity: Severity::Critical,
        reason: format!("{package_name} does not exist (possible hallucination / slopsquatting)"),
    }
}

pub fn missing_version(package_name: &str, version: &str) -> CheckFinding {
    CheckFinding {
        severity: Severity::Critical,
        reason: format!("{package_name}@{version} does not exist (possible hallucinated version)"),
    }
}

#[cfg(test)]
#[path = "existence_tests.rs"]
mod tests;
