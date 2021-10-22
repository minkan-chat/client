//! Data storage and different database backends
use async_trait::async_trait;
use futures::Stream;
use thiserror::Error;

use crate::{seal::Sealed, Result};

#[cfg(target_arch = "wasm32")]
pub(crate) mod indexed_db;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod sqlite;

#[async_trait]
/// A trait for all objects that can be inserted into the database
///
/// # Note
/// This trait is sealed to allow future extension
pub trait Insert: Sealed {
    /// Inserts the instance of [`Self`] into the database.
    async fn insert(&self) -> Result<()>;
}

#[async_trait]
/// A trait for objects that are stored locally and can be retrieved
///
/// # Note
/// This trait is sealed to allow future extension
pub trait Get: Sealed + Sized {
    /// [`crate::Application`] is the root parent. For example, a
    /// [`crate::server::Server`] depends on an [`crate::Application`]
    type Parent;
    /// The type that is used to identify an object. This could be an [`u32`]
    /// or something else.
    type Identifier;
    /// Workaround for streams in traits
    type Stream<'a>: Stream<Item = Result<Self>> + 'a;
    /// Returns a [`Stream`] of all items
    fn get_all(app: &Self::Parent) -> Self::Stream<'_>;
    /// Returns a single item
    async fn get(i: &Self::Identifier, p: &Self::Parent) -> Result<Option<Self>>;
}

#[derive(Debug, Error)]
/// Errors that happen during database operations
pub enum DatabaseError {
    #[error("failed to open the database: {0}")]
    /// Used if we can't open the database. This could be the case because the
    /// user denied access to indexedDB in a webapp or because sqlx failed to
    /// open a connection to the sqlite url
    OpenError(String),
    #[error("error during database migration: {0}")]
    /// Used if a database migration fails.
    /// At an application level, there's nothing you can do except using another
    /// database for application startup
    MigrationError(String),
    #[error("database error")]
    /// Errors that are not handled in any special way
    Other,
}
