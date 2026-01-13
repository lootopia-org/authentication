pub mod auth_factor_handlers;
pub mod auth_handlers;
pub mod auth_service;
mod grpc_impl;
pub mod role_handlers;
pub mod user_handlers;
pub mod constants;

pub use auth_service::AuthService;
pub use constants::*;

pub mod grpc {
    tonic::include_proto!("authentication");
}
