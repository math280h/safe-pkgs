use crate::checks::CheckFinding;
use crate::registries::{RegistryClient, RegistryError};
use crate::types::Severity;

const POPULAR_PACKAGE_SAMPLE_SIZE: usize = 5000;
const OBSCURE_WEEKLY_DOWNLOADS_THRESHOLD: u64 = 50;
const TYPO_DISTANCE_LIMIT: usize = 2;

pub async fn run(
    package_name: &str,
    weekly_downloads: Option<u64>,
    registry_client: &dyn RegistryClient,
) -> Result<Option<CheckFinding>, RegistryError> {
    let weekly_downloads = weekly_downloads.unwrap_or(0);
    if weekly_downloads >= OBSCURE_WEEKLY_DOWNLOADS_THRESHOLD {
        return Ok(None);
    }

    let popular_packages = registry_client
        .fetch_popular_package_names(POPULAR_PACKAGE_SAMPLE_SIZE)
        .await?;

    if popular_packages
        .iter()
        .any(|candidate| candidate == package_name)
    {
        return Ok(None);
    }

    let mut closest_match: Option<(&str, usize)> = None;
    for candidate in &popular_packages {
        let Some(distance) = bounded_levenshtein(package_name, candidate, TYPO_DISTANCE_LIMIT)
        else {
            continue;
        };

        if distance == 0 {
            continue;
        }

        match closest_match {
            Some((_, current_distance)) if current_distance <= distance => {}
            _ => {
                closest_match = Some((candidate.as_str(), distance));
            }
        }
    }

    let Some((candidate, distance)) = closest_match else {
        return Ok(None);
    };

    Ok(Some(CheckFinding {
        severity: Severity::High,
        reason: format!(
            "{package_name} is {distance} edit(s) away from popular package {candidate} and has low adoption ({weekly_downloads} weekly downloads)"
        ),
    }))
}

fn bounded_levenshtein(lhs: &str, rhs: &str, max_distance: usize) -> Option<usize> {
    let lhs_chars = lhs.chars().collect::<Vec<_>>();
    let rhs_chars = rhs.chars().collect::<Vec<_>>();
    let lhs_len = lhs_chars.len();
    let rhs_len = rhs_chars.len();

    if lhs_len.abs_diff(rhs_len) > max_distance {
        return None;
    }

    let mut previous = (0..=rhs_len).collect::<Vec<_>>();
    let mut current = vec![0usize; rhs_len + 1];

    for (i, lhs_char) in lhs_chars.iter().enumerate() {
        current[0] = i + 1;
        let mut row_min = current[0];

        for (j, rhs_char) in rhs_chars.iter().enumerate() {
            let substitution_cost = usize::from(lhs_char != rhs_char);
            let deletion = previous[j + 1] + 1;
            let insertion = current[j] + 1;
            let substitution = previous[j] + substitution_cost;
            current[j + 1] = deletion.min(insertion).min(substitution);
            row_min = row_min.min(current[j + 1]);
        }

        if row_min > max_distance {
            return None;
        }

        std::mem::swap(&mut previous, &mut current);
    }

    let distance = previous[rhs_len];
    (distance <= max_distance).then_some(distance)
}

#[cfg(test)]
#[path = "typosquat_tests.rs"]
mod tests;
