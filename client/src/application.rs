use crate::{database::DatabaseError, Result};

#[non_exhaustive]
#[derive(Debug, Clone)]
/// The base application
///
/// It keeps track where to store the application data
pub struct Application {
    #[cfg(not(target_arch = "wasm32"))]
    /// On native builds, we'll use a sqlite database for better performance
    pool: sqlx::SqlitePool,
}

impl Application {
    #[cfg(not(target_arch = "wasm32"))]
    /// Returns the underlying database pool
    pub(crate) fn pool(&self) -> &sqlx::SqlitePool {
        &self.pool
    }
}
impl Application {
    /// Creates a new [`Application`] instance. If `uri` is set,
    /// it will try to use that uri for the SQLite database driver.
    /// Returns [`crate::Error::Other`] if it can't initalize a database.
    ///
    /// # Note
    /// On wasm targets, `uri` will be ignored.
    ///
    /// # Example
    ///
    /// ```
    /// # use minkan_client::Application;
    /// # tokio_test::block_on(async {
    /// let app = Application::new("sqlite::memory:").await.unwrap();
    /// # })
    pub async fn new(uri: impl AsRef<str>) -> Result<Self> {
        #[cfg(not(target_arch = "wasm32"))]
        let pool = {
            let pool = sqlx::SqlitePool::connect(uri.as_ref())
                .await
                .map_err(|e| DatabaseError::OpenError(e.to_string()))?;

            sqlx::migrate!("./migrations/")
                .run(&pool)
                .await
                .map_err(|e| DatabaseError::MigrationError(e.to_string()))?;
            pool
        };
        #[cfg(target_arch = "wasm32")]
        {
            todo!("database backend for wasm is not ready yet")
        }
        Ok(Self { pool })
    }
}
