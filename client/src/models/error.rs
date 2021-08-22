use chrono::{DateTime, Utc};
use serde::Deserialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("{0}")]
    UnknownUser(String),
    #[error("{0}")]
    InvalidMasterPasswordHash(String),
    #[error("description")]
    UserSuspended {
        description: String,
        /// The date and time since the user is suspended in utc
        since: DateTime<Utc>,
        /// The reason for the suspension
        reason: String,
    },
    #[error("Failed to connect to the authentication server.")]
    NoConnection,
}

#[derive(Error, Debug, Deserialize)]
#[serde(tag = "__typename")]
pub enum SignupError {
    #[error("{description}")]
    UsernameUnavailable { description: String },
    #[error("{description}")]
    InvalidUsername { description: String },
    #[error("{description}")]
    CertificateTaken { description: String },
    #[error("{description}")]
    InvalidCertificate { description: String },
    #[error("{description}")]
    InvalidSignature { description: String },
    #[error("{description}")]
    InvalidChallenge { description: String },
    #[error("Failed to connect to the registration server.")]
    #[serde(skip)]
    NoConnection,
}

#[derive(Error, Debug, Clone)]
pub enum KeyError {
    #[error("Invalid key password")]
    InvalidKeyPassword,
    #[error("The key has an invalid algorithm")]
    InvalidKeyAlgo,
    #[error("There is no such key")]
    NoSuchKey,
}
