pub mod error;
pub mod user;
use serde::{Deserialize, Serialize};
pub use user::User;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenPair {
    /// Used for authentication
    access_token: String,
    /// Used to get a new token pair after the access token has expried
    refresh_token: String,
}
