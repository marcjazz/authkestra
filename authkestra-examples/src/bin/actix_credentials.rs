use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use async_trait::async_trait;
use authkestra::flow::CredentialsFlow;
use authkestra_actix::AuthSession;
use authkestra_engine::{error::AuthError, state::Identity, CredentialsProvider, UserMapper};
use authkestra_engine::{AuthEngine, StatefulAuthEngine};
use authkestra_session::SessionStore;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

// 1. Define Credentials
#[derive(Deserialize)]
pub struct LoginCredentials {
    pub username: String,
    pub password: String,
}

// 2. Implement a Mock CredentialsProvider
pub struct MyCredentialsProvider;

#[async_trait]
impl CredentialsProvider for MyCredentialsProvider {
    type Credentials = LoginCredentials;

    async fn authenticate(&self, creds: Self::Credentials) -> Result<Identity, AuthError> {
        if creds.username == "admin" && creds.password == "password" {
            Ok(Identity {
                provider_id: "credentials".to_string(),
                external_id: "admin-id-123".to_string(),
                email: Some("admin@example.com".to_string()),
                username: Some("admin".to_string()),
                attributes: HashMap::new(),
            })
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }
}

// 3. Define Local User and Mapper
#[derive(Debug, Clone, serde::Serialize)]
pub struct LocalUser {
    pub id: i32,
    pub username: String,
    pub role: String,
}

pub struct MyUserMapper;

#[async_trait]
impl UserMapper for MyUserMapper {
    type LocalUser = LocalUser;

    async fn map_user(&self, identity: &Identity) -> Result<Self::LocalUser, AuthError> {
        Ok(LocalUser {
            id: 1,
            username: identity.username.clone().unwrap_or_default(),
            role: "admin".to_string(),
        })
    }
}

// 4. App State
struct AppState {
    auth_flow: Arc<CredentialsFlow<MyCredentialsProvider, MyUserMapper>>,
    auth_engine: StatefulAuthEngine,
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(
            r#"
            <form action="/login" method="post">
                <input type="text" name="username" placeholder="Username" />
                <input type="password" name="password" placeholder="Password" />
                <button type="submit">Login</button>
            </form>
        "#,
        )
}

#[post("/login")]
async fn login(
    data: web::Data<AppState>,
    creds: web::Form<LoginCredentials>,
) -> Result<HttpResponse, actix_web::Error> {
    let (identity, local_user) = match data.auth_flow.authenticate(creds.into_inner()).await {
        Ok(res) => res,
        Err(e) => return Ok(HttpResponse::Unauthorized().body(e.to_string())),
    };

    if let Some(user) = &local_user {
        println!("Logged in as local user: {user:?}");
    }

    let session = match data.auth_engine.create_session(identity).await {
        Ok(s) => s,
        Err(e) => return Ok(HttpResponse::InternalServerError().body(e.to_string())),
    };

    let cookie = authkestra_actix::helpers::create_actix_cookie(
        &data.auth_engine.session_config,
        session.id,
    );

    Ok(HttpResponse::Found()
        .append_header(("Location", "/protected"))
        .cookie(cookie)
        .finish())
}

#[get("/protected")]
async fn protected(AuthSession(session): AuthSession) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Hello, {}! Your ID is {}. Session ID: {}",
        session.identity.username.clone().unwrap_or_default(),
        session.identity.external_id,
        session.id
    ))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let provider = MyCredentialsProvider;
    let mapper = MyUserMapper;
    let auth_flow = Arc::new(CredentialsFlow::with_mapper(provider, mapper));

    let session_store: Arc<dyn SessionStore> =
        Arc::new(authkestra_session_memory::MemoryStore::default());

    let auth_engine = AuthEngine::builder()
        .session_store(session_store.clone())
        .build();

    let app_state = web::Data::new(AppState {
        auth_flow,
        auth_engine: auth_engine.clone(),
    });

    println!("🚀 Actix Credentials Example running at http://localhost:3000");

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(web::Data::new(auth_engine.clone()))
            .app_data(web::Data::new(session_store.clone()))
            .app_data(web::Data::new(auth_engine.session_config.clone()))
            .service(index)
            .service(login)
            .service(protected)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}
