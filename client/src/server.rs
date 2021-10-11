//! The backend the client talks to
use url::Url;

#[non_exhaustive]
#[derive(Debug)]
/// A server the client can talk to
///
/// A server is a running instance of the [minkan server][1]. It should not be
/// confused with a guild.
///
/// [1]: https://github.com/minkan-chat/server
pub struct Server {
    /// The GraphQL API endpoint
    ///
    /// Usually, this is something like ``example.com/graphql``
    api_endpoint: Url,
}
