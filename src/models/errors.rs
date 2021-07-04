use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("Failed to connect to the authentication server.")]
    NoConnection,
    #[error("The server did not accept the password sent.")]
    InvalidPassword,
}
