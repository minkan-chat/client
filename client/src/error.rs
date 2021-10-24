//! Different error types

use crate::{actor::Actor, database::DatabaseError};
use sequoia_openpgp::Cert;
use serde::Deserialize;
use thiserror::Error;

/// Macro to avoid code duplication of the `description` and `hint` field
macro_rules! api_errors {
    ($(
        $(#[$attr:meta])*
        $name:ident $({
            $(
                $(#[$inner_attr:meta])*
                $field:ident: $field_type:ty$(,)?
            ),*
        }$(,)?)?
    ),*) => {
        #[derive(Debug, Error, Deserialize)]
        #[non_exhaustive]
        #[serde(tag = "__typename")]
        /// This error type maps to the graphql error types
        pub enum ApiError {
            $(
                #[error("{description}")]
                $(#[$attr])*
                $name {
                    /// The error description sent by the server
                    description: String,
                    /// A hint how to prevent this error
                    hint: Option<String>,
                    $($(
                        $(#[$inner_attr])*
                        $field: $field_type
                    ),*)?
                }
            ),*
        }
    };
}

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
    /// Errors that may occur while sending http requests to the api
    ReqwestError(#[from] reqwest::Error),
    #[error(transparent)]
    /// Errors that are associated with OpenPGP
    OpenPGPError(#[from] sequoia_openpgp::Error),
    #[error(transparent)]
    /// Database operation errors
    DatabaseError(#[from] DatabaseError),
    #[error(transparent)]
    /// a catch-all error. If no other error matches, this will
    Other(#[from] anyhow::Error),
}

api_errors! {
    /// This error means that another [`Actor`]'s PGP certificate has the same
    /// fingerprint. The chance that this will happen by accident is incredible
    /// low. It is way more likely that the client has a bug and sent the same
    /// [`Cert`] twice.
    CertificateTaken {
        #[serde(
        rename = "certificate",
        serialize_with = "crate::serialize_cert",
        deserialize_with = "crate::deserialize_cert_box"
        )]
        /// The [`Cert`] that was sent in the input
        cert: Box<Cert>,
    },
    /// The server failed to parse the [`Cert`]
    InvalidCertificate,
    /// The fingerprint was invalid. That means, it is not a valid hex string.
    InvalidCertificateFingerprint,
    /// The challenge provided is not valid.
    InvalidChallenge {
        /// The supplied challenge
        challenge: String,
    },
    /// The server either failed to parse the signature or parsed the signature
    /// successful but failed to verify the signature. In the latter case, the
    /// server would probably respond with ``UnexpectedSigner`` instead.
    InvalidSignature,
    /// The supplied username is invalid. This error occurs mostly if the
    /// username contains invalid characters or otherwise does not meet the
    /// criteria.
    InvalidUsername,
    /// The server didn't find a user with that name
    NoSuchUser {
        /// The name given in the input
        name: String,
    },
    /// An unexpected error. Probably something internal like a database error
    Unexpected,
    /// The server could verify signature but detected that the signature is not
    /// made by the expected signer.
    UnexpectedSigner {
        /// The expected [`Actor`]
        expected: Option<Box<dyn Actor>>,
        /// The actual [`Actor`]
        got: Option<Box<dyn Actor>>,
    },
    /// The server does not know a certificate with the given fingerprint
    UnknownCertificate {
        /// The given fingerprint
        fingerprint: String,
    },
    /// The supplied username is unavailable. This error usually occurs when
    /// another user has the same name. However, it could also occur because the
    /// name violates the name policy.
    UsernameUnavailable {
        /// The supplied name
        name: String,
    },
}

#[derive(Debug, Error)]
#[non_exhaustive]
/// Errors that may occur while parsing data
pub enum ParseError {
    #[error("url has no host")]
    /// The url has no host
    UrlWithoutHost {
        /// The url that has no host
        url: url::Url,
    },
    #[error(transparent)]
    /// Errors from the [`url`] crate
    UrlError(#[from] url::ParseError),
}
