use authkestra_flow::ClientCredentialsFlow;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example using a hypothetical provider
    // In a real scenario, you would use your OAuth2 provider's client credentials credentials
    let client_id = std::env::var("CLIENT_ID").unwrap_or_else(|_| "your_client_id".to_string());
    let client_secret =
        std::env::var("CLIENT_SECRET").unwrap_or_else(|_| "your_client_secret".to_string());
    let token_url = std::env::var("TOKEN_URL")
        .unwrap_or_else(|_| "https://example.com/oauth/token".to_string());

    println!("Starting Client Credentials Flow...");

    let flow = ClientCredentialsFlow::new(client_id, client_secret, token_url);

    // Request a token with optional scopes
    let scopes = ["read", "write"];
    match flow.get_token(Some(&scopes)).await {
        Ok(token) => {
            println!("Successfully obtained access token!");
            println!("Access Token: {}", token.access_token);
            if let Some(expires_in) = token.expires_in {
                println!("Expires in: {} seconds", expires_in);
            }
            if let Some(scope) = token.scope {
                println!("Scopes: {}", scope);
            }
        }
        Err(e) => {
            eprintln!("Failed to obtain access token: {}", e);
            println!("\nTip: Set CLIENT_ID, CLIENT_SECRET, and TOKEN_URL environment variables to test with a real provider.");
        }
    }

    Ok(())
}
