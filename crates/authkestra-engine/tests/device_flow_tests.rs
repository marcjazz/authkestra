use authkestra_engine::flow::device_flow::DeviceFlow;
use serde_json::json;
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
