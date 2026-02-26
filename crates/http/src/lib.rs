use reqwest::{Client, RequestBuilder, Response, StatusCode, header::HeaderMap};
use safe_pkgs_core::RegistryError;
use serde::de::DeserializeOwned;
use std::time::Duration;

const DEFAULT_MAX_ATTEMPTS: u8 = 3;
const DEFAULT_INITIAL_BACKOFF_MILLIS: u64 = 250;
const DEFAULT_MAX_BACKOFF_SECS: u64 = 5;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 20;

pub const DEFAULT_USER_AGENT: &str = concat!("safe-pkgs/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            initial_backoff: Duration::from_millis(DEFAULT_INITIAL_BACKOFF_MILLIS),
            max_backoff: Duration::from_secs(DEFAULT_MAX_BACKOFF_SECS),
        }
    }
}

pub fn build_http_client() -> Client {
    let user_agent = std::env::var("SAFE_PKGS_HTTP_USER_AGENT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_USER_AGENT.to_string());

    Client::builder()
        .user_agent(user_agent)
        .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS))
        .build()
        .unwrap_or_else(|_| Client::new())
}

pub async fn send_with_retry<F>(
    mut build_request: F,
    operation: &str,
    policy: RetryPolicy,
) -> Result<Response, RegistryError>
where
    F: FnMut() -> RequestBuilder,
{
    let max_attempts = policy.max_attempts.max(1);
    let mut attempt = 1u8;
    loop {
        let response = build_request().send().await;

        match response {
            Ok(response) => {
                if attempt < max_attempts && should_retry_status(response.status()) {
                    let delay = compute_retry_delay(
                        attempt,
                        policy,
                        parse_retry_after_seconds(response.headers()).map(Duration::from_secs),
                    );
                    tokio::time::sleep(delay).await;
                    attempt = attempt.saturating_add(1);
                    continue;
                }

                return Ok(response);
            }
            Err(source) => {
                if attempt < max_attempts && should_retry_transport_error(&source) {
                    let delay = compute_retry_delay(attempt, policy, None);
                    tokio::time::sleep(delay).await;
                    attempt = attempt.saturating_add(1);
                    continue;
                }

                return Err(transport_error(operation, source));
            }
        }
    }
}

pub fn map_status_error(operation: &str, status: StatusCode) -> RegistryError {
    RegistryError::Transport {
        message: format!("{operation} returned status {status}"),
    }
}

pub async fn parse_json<T>(response: Response, operation: &str) -> Result<T, RegistryError>
where
    T: DeserializeOwned,
{
    response
        .json()
        .await
        .map_err(|source| RegistryError::InvalidResponse {
            message: format!("failed to parse {operation} JSON: {source}"),
        })
}

pub fn transport_error(operation: &str, source: reqwest::Error) -> RegistryError {
    RegistryError::Transport {
        message: format!("{operation} request failed: {source}"),
    }
}

fn should_retry_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn should_retry_transport_error(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_timeout() || error.is_request()
}

fn parse_retry_after_seconds(headers: &HeaderMap) -> Option<u64> {
    let raw = headers.get("retry-after")?.to_str().ok()?.trim();
    raw.parse::<u64>().ok().map(|value| value.max(1))
}

fn compute_retry_delay(
    attempt: u8,
    policy: RetryPolicy,
    retry_after: Option<Duration>,
) -> Duration {
    let fallback = exponential_backoff(attempt, policy.initial_backoff, policy.max_backoff);
    match retry_after {
        Some(delay) => {
            let bounded = if delay > policy.max_backoff {
                policy.max_backoff
            } else {
                delay
            };
            if bounded.is_zero() {
                Duration::from_millis(1)
            } else {
                bounded
            }
        }
        None => fallback,
    }
}

fn exponential_backoff(attempt: u8, initial_backoff: Duration, max_backoff: Duration) -> Duration {
    let shift = u32::from(attempt.saturating_sub(1)).min(16);
    let multiplier = 2u128.pow(shift);
    let initial_ms = initial_backoff.as_millis();
    let raw_ms = initial_ms.saturating_mul(multiplier);
    let max_ms = max_backoff.as_millis();
    let bounded_ms = raw_ms.min(max_ms);
    let bounded_ms_u64 = u64::try_from(bounded_ms).unwrap_or(u64::MAX);
    Duration::from_millis(bounded_ms_u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn exponential_backoff_caps_at_maximum() {
        let delay = exponential_backoff(8, Duration::from_millis(100), Duration::from_secs(1));
        assert_eq!(delay, Duration::from_secs(1));
    }

    #[test]
    fn compute_retry_delay_prefers_retry_after_when_present() {
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
        };

        let delay = compute_retry_delay(1, policy, Some(Duration::from_secs(2)));
        assert_eq!(delay, Duration::from_secs(2));
    }

    #[tokio::test]
    async fn send_with_retry_retries_retryable_statuses() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/retry"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
            .expect(2)
            .mount(&server)
            .await;

        let client = build_http_client();
        let url = format!("{}/retry", server.uri());
        let response = send_with_retry(
            || client.get(&url),
            "retry test",
            RetryPolicy {
                max_attempts: 2,
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(10),
            },
        )
        .await
        .expect("request should complete with response");

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn send_with_retry_retries_transport_errors() {
        let client = build_http_client();
        let mut attempts = 0usize;
        let err = send_with_retry(
            || {
                attempts = attempts.saturating_add(1);
                client.get("http://127.0.0.1:9")
            },
            "transport retry test",
            RetryPolicy {
                max_attempts: 2,
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(2),
            },
        )
        .await
        .expect_err("transport errors should bubble up after retries");

        assert!(matches!(err, RegistryError::Transport { .. }));
        assert_eq!(attempts, 2);
    }
}
