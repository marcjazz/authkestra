use authkestra_engine::flow::device_flow::DeviceFlow;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_initiate_device_authorization() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/device_auth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhzjCJRS2s",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
            "expires_in": 1800,
            "interval": 5
        })))
        .mount(&mock_server)
        .await;

    let flow = DeviceFlow::new(
        "test_client_id".to_string(),
        format!("{}/device_auth", mock_server.uri()),
        format!("{}/token", mock_server.uri()),
    );

    let response = flow
        .initiate_device_authorization(&["openid", "profile"])
        .await
        .unwrap();

    assert_eq!(
        response.device_code,
        "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhzjCJRS2s"
    );
    assert_eq!(response.user_code, "WDJB-MJHT");
    assert_eq!(response.expires_in, 1800);
}

/// Regression test for #306: `poll_for_token` is an `async fn`, so it must
/// wait on a timer rather than blocking the thread.
///
/// It used to wait with `std::thread::sleep`, parking the worker for the whole
/// interval on every iteration — starving other tasks on a multi-thread
/// runtime, and stalling the entire executor on a current-thread one.
///
/// Two independent signals, both of which the blocking version fails:
///
/// - A sibling task whose timer fires *during* the poll interval must have run
///   by the time polling finishes. Under `std::thread::sleep` on this
///   current-thread runtime the executor cannot poll it at all.
/// - With the clock paused, a real timer costs no wall-clock time, because
///   Tokio auto-advances virtual time whenever the runtime goes idle.
///   `std::thread::sleep` ignores the paused clock and burns the full five
///   seconds for real.
#[tokio::test(start_paused = true)]
async fn poll_for_token_waits_on_a_timer_rather_than_blocking_the_runtime() {
    let mock_server = MockServer::start().await;

    // First poll: not authorized yet, so the flow waits out one interval.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({ "error": "authorization_pending" })),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Second poll: the user has approved.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "at_12345",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&mock_server)
        .await;

    let flow = DeviceFlow::new(
        "test_client_id".to_string(),
        format!("{}/device_auth", mock_server.uri()),
        format!("{}/token", mock_server.uri()),
    );

    // Fires partway through the five-second interval, so it can only have run
    // if the runtime stayed free while the flow was waiting.
    let ran_during_the_wait = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran_during_the_wait);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        flag.store(true, Ordering::SeqCst);
    });

    let started = Instant::now();
    let token = flow
        .poll_for_token("device_code_abc", Some(5))
        .await
        .expect("polling should return the token once authorization completes");
    let wall_clock = started.elapsed();

    assert_eq!(token.access_token, "at_12345");
    assert!(
        ran_during_the_wait.load(Ordering::SeqCst),
        "a sibling task never got to run: the poll interval blocked the runtime"
    );
    assert!(
        wall_clock < Duration::from_secs(1),
        "waiting cost {wall_clock:?} of real time under a paused clock, so it was not a timer"
    );
}

/// `slow_down` must lengthen the interval without changing how it waits.
#[tokio::test(start_paused = true)]
async fn slow_down_extends_the_interval_and_still_yields() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({ "error": "slow_down" })))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "at_after_slow_down",
            "token_type": "Bearer"
        })))
        .mount(&mock_server)
        .await;

    let flow = DeviceFlow::new(
        "test_client_id".to_string(),
        format!("{}/device_auth", mock_server.uri()),
        format!("{}/token", mock_server.uri()),
    );

    let started = Instant::now();
    let token = flow
        .poll_for_token("device_code_abc", Some(5))
        .await
        .expect("polling should recover from slow_down");

    assert_eq!(token.access_token, "at_after_slow_down");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the lengthened interval was waited out by blocking the thread"
    );
}
