use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("Failed to connect to the authentication server.")]
    NoConnection,
    #[error("The server did not accept the password sent.")]
    InvalidPassword,
}

#[derive(Error, Debug)]
pub enum RegistrationError {
    #[error("Failed to connect to the registration server.")]
    NoConnection,
    #[error("Username is unavailable.")]
    UsernameUnavailable,
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
