use crate::database::DatabaseError;
use serde::Deserialize;
use thiserror::Error;
/// A type alias for Results which return [`enum@Error`]
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
#[non_exhaustive]
/// The errors that may occur when using this library
pub enum Error {
    #[error(transparent)]
    /// Special case to represent errors during parsing of some data
    ParseError(#[from] ParseError),
    #[error(transparent)]
    /// Maps to the graphql api errors
    ApiError(#[from] ApiError),
    #[error(transparent)]
    /// Database operation errors
    DatabaseError(#[from] DatabaseError),
    #[error(transparent)]
    /// a catch-all error. If no other error matches, this will
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Error, Deserialize)]
#[non_exhaustive]
#[serde(tag = "__typename")]
/// Represents the different errors the server may return
pub enum ApiError {}

#[derive(Debug, Error)]
#[non_exhaustive]
/// Errors that may occur while parsing data
pub enum ParseError {
    #[error("url has no host")]
    UrlWithoutHost { url: url::Url },
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
}
