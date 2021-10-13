use directories::ProjectDirs;

use crate::{database::Database, Result};

#[non_exhaustive]
#[derive(Debug)]
/// The base application
///
/// It keeps track where to store the data for different server instances
pub struct Application {
    // the database, the application will use
    database: Database,
}

impl Application {
    /// Creates a new [`Application`] instance. If ``path`` is set,
    /// it will try to use that as the project dir.
    ///
    /// # Note
    /// On wasm targets, ``path`` will be ignored
    pub async fn new(_path: impl Into<ProjectDirs>) -> Result<Self> {
        todo!()
    }
}
