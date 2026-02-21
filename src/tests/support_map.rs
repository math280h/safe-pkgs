use super::*;
use crate::checks::CheckDescriptor;
use crate::registries::CheckSupportRow;

#[test]
fn render_support_map_without_color_includes_sections() {
    let rendered = render_support_map(false);
    assert!(rendered.contains("safe-pkgs support map"));
    assert!(rendered.contains("Registry Coverage"));
    assert!(rendered.contains("Checks"));
    assert!(rendered.contains("npm"));
    assert!(rendered.contains("cargo"));
    assert!(rendered.contains("pypi"));
}

#[test]
fn render_support_map_with_color_includes_ansi_codes() {
    let rendered = render_support_map(true);
    assert!(rendered.contains("\x1b["));
}

#[test]
fn flags_for_check_marks_required_inputs() {
    let descriptor = CheckDescriptor {
        id: "demo",
        key: "demo",
        description: "test",
        needs_weekly_downloads: true,
        needs_advisories: false,
    };
    assert_eq!(flags_for_check(descriptor), "W-");

    let descriptor = CheckDescriptor {
        id: "demo",
        key: "demo",
        description: "test",
        needs_weekly_downloads: false,
        needs_advisories: true,
    };
    assert_eq!(flags_for_check(descriptor), "-A");
}

#[test]
fn support_cell_renders_yes_and_no() {
    let yes_plain = support_cell(true, 3, false);
    let no_plain = support_cell(false, 2, false);
    assert_eq!(yes_plain.trim(), "yes");
    assert_eq!(no_plain.trim(), "no");

    let yes_colored = support_cell(true, 3, true);
    let no_colored = support_cell(false, 2, true);
    assert!(yes_colored.contains("\x1b[32m"));
    assert!(no_colored.contains("\x1b[31m"));
}

#[test]
fn support_lookup_matches_registry_and_check() {
    let rows = vec![
        CheckSupportRow {
            registry: "npm",
            check: "existence",
            supported: true,
        },
        CheckSupportRow {
            registry: "npm",
            check: "advisory",
            supported: false,
        },
    ];

    assert!(is_supported_for_registry(&rows, "npm", "existence"));
    assert!(!is_supported_for_registry(&rows, "npm", "advisory"));
    assert!(!is_supported_for_registry(&rows, "cargo", "existence"));
}
