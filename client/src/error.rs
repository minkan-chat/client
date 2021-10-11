use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Deserialize, Error)]
#[serde(tag = "__typename")]
#[non_exhaustive]
/// The errors that may occur when using this library
pub enum Error {
    #[error(transparent)]
    #[serde(skip)]
    /// a catch-all error. If no other error matches, this will
    Other(#[from] anyhow::Error),
}

/// A type alias for Results which return [`enum@Error`]
pub type Result<T> = core::result::Result<T, Error>;
