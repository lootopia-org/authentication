use diesel::r2d2::{ConnectionManager, Pool, PoolError};
use diesel::PgConnection;
use diesel::ConnectionError;
use std::time::Duration;

use crate::domain::{AuthError, AuthResult};

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

pub fn create_pool(database_url: &str, max_size: u32) -> Result<DbPool, PoolError> {
    let manager = ConnectionManager::<PgConnection>::new(database_url);

    Pool::builder()
        .max_size(max_size)
        .connection_timeout(Duration::from_secs(30))
        .build(manager)
}

pub fn get_connection(
    pool: &DbPool,
) -> AuthResult<diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<diesel::PgConnection>>> {
    pool.get().map_err(|e| AuthError::Pool(ConnectionError::BadConnection(e.to_string())))
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_pool_creation() {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_default();
        if !database_url.is_empty() {
            let pool = create_pool(&database_url, 5);
            assert!(pool.is_ok());
        }
    }
}
