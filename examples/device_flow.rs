use authkestra_flow::DeviceFlow;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // GitHub's Device Authorization Flow endpoints
    let client_id =
        std::env::var("GITHUB_CLIENT_ID").unwrap_or_else(|_| "Iv1.your_client_id".to_string());
    let device_auth_url = "https://github.com/login/device/code";
    let token_url = "https://github.com/login/oauth/access_token";

    let flow = DeviceFlow::new(
        client_id,
        device_auth_url.to_string(),
        token_url.to_string(),
    );

    println!("Initiating device authorization flow...");

    // 1. Request device authorization
    let device_resp = flow
        .initiate_device_authorization(&["user", "repo"])
        .await?;

    println!(
        "\n1. Open your browser and go to: {}",
        device_resp.verification_uri
    );
    println!("2. Enter the code: {}", device_resp.user_code);

    if let Some(complete_uri) = &device_resp.verification_uri_complete {
        println!("\nOR just open this URL directly: {}", complete_uri);
    }

    println!("\nWaiting for authorization...");

    // 2. Poll for the token
    match flow
        .poll_for_token(&device_resp.device_code, device_resp.interval)
        .await
    {
        Ok(token) => {
            println!("\nAuthorization successful!");
            println!("Access Token: {}", token.access_token);
            if let Some(scope) = token.scope {
                println!("Scopes: {}", scope);
            }
        }
        Err(e) => {
            eprintln!("\nAuthorization failed: {}", e);
        }
    }

    Ok(())
}
