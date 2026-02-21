//! Terminal renderer for registry/check support information.

use crate::checks::CheckDescriptor;
use crate::registries::CheckSupportRow;

/// Renders the check-support map in a terminal-friendly format.
pub fn render_support_map(use_color: bool) -> String {
    let catalog = crate::registries::register_default_catalog();
    let support_rows = catalog.check_support_rows();
    let registry_keys = catalog.package_registry_keys();
    let descriptors = crate::checks::check_descriptors();
    let support_matrix = descriptors
        .iter()
        .map(|descriptor| {
            registry_keys
                .iter()
                .map(|registry_key| {
                    is_supported_for_registry(&support_rows, registry_key, descriptor.id)
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let check_col_width = descriptors
        .iter()
        .map(|descriptor| descriptor.key.len())
        .max()
        .unwrap_or("check".len())
        .max("check".len());
    let flags_col_width = "flags".len().max(2);
    let registry_col_widths = registry_keys
        .iter()
        .map(|key| key.len().max(3))
        .collect::<Vec<_>>();

    let mut lines = Vec::new();
    lines.push(style("safe-pkgs support map", "1;36", use_color));
    lines.push(format!(
        "checks: {} | registries: {}",
        descriptors.len(),
        registry_keys.len()
    ));
    lines.push(format!(
        "legend: flags [W,A] where W=needs weekly downloads, A=needs advisories; {}=supported, {}=unsupported",
        style("yes", "32", use_color),
        style("no", "31", use_color),
    ));
    lines.push(String::new());
    lines.push(style("Registry Coverage", "1;36", use_color));

    for (registry_index, registry_key) in registry_keys.iter().enumerate() {
        let supported_count = support_matrix
            .iter()
            .filter(|supported| supported[registry_index])
            .count();
        let total_count = descriptors.len();
        let percent = if total_count == 0 {
            100u32
        } else {
            ((supported_count as f64 / total_count as f64) * 100.0).round() as u32
        };
        let coverage = format!("{supported_count}/{total_count} ({percent}%)");
        lines.push(format!(
            "  {:<10} {}",
            style(registry_key, "1", use_color),
            if supported_count == total_count {
                style(&coverage, "32", use_color)
            } else {
                style(&coverage, "33", use_color)
            }
        ));

        let unsupported = descriptors
            .iter()
            .enumerate()
            .filter_map(|(row_index, descriptor)| {
                (!support_matrix[row_index][registry_index]).then_some(descriptor.key)
            })
            .collect::<Vec<_>>();

        if !unsupported.is_empty() {
            lines.push(format!(
                "    unsupported: {}",
                style(&unsupported.join(", "), "31", use_color)
            ));
        }
    }

    lines.push(String::new());
    lines.push(style("Checks", "1;36", use_color));

    let mut header = format!(
        "{:<check_col_width$}  {:<flags_col_width$}",
        "check", "flags"
    );
    for (registry_key, width) in registry_keys.iter().zip(registry_col_widths.iter()) {
        header.push_str("  ");
        header.push_str(format!("{:<width$}", registry_key, width = *width).as_str());
    }
    header.push_str("  description");
    lines.push(style(&header, "1;36", use_color));
    lines.push("-".repeat(header.len()));

    for (row_index, descriptor) in descriptors.iter().enumerate() {
        let check_color = if support_matrix[row_index].iter().all(|supported| *supported) {
            "1"
        } else {
            "1;33"
        };
        let mut line = String::new();
        line.push_str(&style(
            format!("{:<check_col_width$}", descriptor.key).as_str(),
            check_color,
            use_color,
        ));
        line.push_str("  ");
        line.push_str(render_flags(*descriptor, flags_col_width, use_color).as_str());

        for (registry_index, width) in registry_col_widths.iter().enumerate() {
            line.push_str("  ");
            line.push_str(
                support_cell(support_matrix[row_index][registry_index], *width, use_color).as_str(),
            );
        }
        line.push_str("  ");
        line.push_str(descriptor.description);
        lines.push(line);
    }

    lines.join("\n")
}

fn is_supported_for_registry(
    support_rows: &[CheckSupportRow],
    registry_key: &str,
    check: &str,
) -> bool {
    support_rows
        .iter()
        .any(|row| row.registry == registry_key && row.check == check && row.supported)
}

fn render_flags(descriptor: CheckDescriptor, width: usize, use_color: bool) -> String {
    let raw = format!("{:<width$}", flags_for_check(descriptor), width = width);
    if !use_color {
        return raw;
    }

    let mut result = String::new();
    for ch in raw.chars() {
        match ch {
            'W' | 'A' => result.push_str(style(&ch.to_string(), "33", use_color).as_str()),
            '-' => result.push_str(style("-", "2", use_color).as_str()),
            _ => result.push(ch),
        }
    }
    result
}

fn flags_for_check(descriptor: CheckDescriptor) -> String {
    format!(
        "{}{}",
        if descriptor.needs_weekly_downloads {
            "W"
        } else {
            "-"
        },
        if descriptor.needs_advisories {
            "A"
        } else {
            "-"
        }
    )
}

fn support_cell(supported: bool, width: usize, use_color: bool) -> String {
    let raw = format!(
        "{:<width$}",
        if supported { "yes" } else { "no" },
        width = width
    );
    if supported {
        style(&raw, "32", use_color)
    } else {
        style(&raw, "31", use_color)
    }
}

fn style(value: &str, ansi_code: &str, use_color: bool) -> String {
    if use_color {
        return format!("\x1b[{ansi_code}m{value}\x1b[0m");
    }

    value.to_string()
}

#[cfg(test)]
#[path = "tests/support_map.rs"]
mod tests;
