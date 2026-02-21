use super::*;

#[test]
fn check_support_map_marks_install_scripts_only_for_npm() {
    let catalog = register_default_catalog();
    let rows = catalog.check_support_rows();

    let npm_install_script = rows
        .iter()
        .find(|row| row.registry == "npm" && row.check == "install_script")
        .expect("npm install_script row");
    let cargo_install_script = rows
        .iter()
        .find(|row| row.registry == "cargo" && row.check == "install_script")
        .expect("cargo install_script row");
    let pypi_install_script = rows
        .iter()
        .find(|row| row.registry == "pypi" && row.check == "install_script")
        .expect("pypi install_script row");

    assert!(npm_install_script.supported);
    assert!(!cargo_install_script.supported);
    assert!(!pypi_install_script.supported);
}

#[test]
fn check_support_map_has_every_registry_check_pair() {
    let catalog = register_default_catalog();
    let rows = catalog.check_support_rows();
    let check_count = crate::checks::check_descriptors().len();

    let expected = supported_package_registry_keys().len() * check_count;
    assert_eq!(rows.len(), expected);
}
