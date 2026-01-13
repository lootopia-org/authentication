mod config;
mod db;
mod domain;
mod middleware;
mod models;
mod services;

use config::{validate_config, Config};
use db::create_pool;
use http::{header, HeaderValue, Method};
use middleware::AuthMiddleware;
use services::grpc::authentication_service_server::AuthenticationServiceServer;
use services::AuthService;
use tonic::transport::Server;
use tonic_reflection::server::Builder as ReflectionBuilder;
use tower_http::cors::CorsLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    init_logging();

    info!("Starting authentication service...");

    let config = Config::from_env().expect("Failed to load configuration from environment");

    info!(pool_size = config.db_pool_size, "Configuration loaded");
    validate_config(&config);

    info!("Creating database connection pool...");
    let pool = create_pool(&config.database_url, config.db_pool_size)
        .expect("Failed to create database connection pool");
    info!("Database connection pool created successfully");

    let auth_middleware = AuthMiddleware::new(config.clone(), pool.clone());
    let auth_service = AuthService::new(config.clone(), pool.clone());
    let addr = config.grpc_addr.parse()?;

    let file_descriptor_set = include_bytes!("../target/auth_descriptor.bin");
    let reflection_service = ReflectionBuilder::configure()
        .register_encoded_file_descriptor_set(file_descriptor_set)
        .build_v1()
        .expect("Failed to build reflection service");

    info!("Authentication gRPC server listening on {}", addr);

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:44875".parse::<HeaderValue>().unwrap())
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT])
        .expose_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true);

    Server::builder()
        .layer(cors)
        .layer(tonic_web::GrpcWebLayer::new())
        .add_service(AuthenticationServiceServer::with_interceptor(
            auth_service,
            auth_middleware,
        ))
        .add_service(reflection_service)
        .serve(addr)
        .await?;

    Ok(())
}

fn init_logging() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "authentication=debug,tower_http=debug,axum=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
