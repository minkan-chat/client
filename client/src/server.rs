//! The backend the client talks to

use url::Url;

use crate::{error::ParseError, seal::Sealed, Application, Error, Result};

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
    /// Usually, this is something like `https://example.com/graphql`
    pub(crate) api_endpoint: Url,
    /// The name an end-user can give to a server so they can easier identify it
    pub(crate) nickname: Option<String>,
    /// The application the server can use to do interactions with the database
    pub(crate) app: Application,
}

impl Sealed for Server {}

impl Server {
    /// Creates a new server with the given url as the graphql api endpoint
    ///
    /// # Note
    /// Call [`crate::database::Insert::insert`] on [`Self`] to actually insert this
    /// server instance into the database.
    ///
    /// # Example
    ///
    /// ```
    /// # use url::Url;
    /// # use minkan_client::server::Server;
    /// # use minkan_client::Application;
    /// # tokio_test::block_on( async {
    /// let app = Application::new("sqlite::memory:").await.unwrap();
    /// let api_endpoint = Url::parse("https://example.com/graphql").unwrap();
    /// let server = Server::new(api_endpoint, None, app).await.unwrap();
    /// # })
    /// ```
    pub async fn new(
        api_endpoint: Url,
        nickname: Option<String>,
        app: Application,
    ) -> Result<Self> {
        // if the url has no host, it is invalid
        if !api_endpoint.has_host() {
            return Err(Error::ParseError(ParseError::UrlWithoutHost {
                url: api_endpoint,
            }));
        }
        Ok(Self {
            api_endpoint,
            nickname,
            app,
        })
    }

    /// Returns the [`Url`] of the API used for this server.
    /// It can be useful to access the [`Url`] directly in cases where you want
    /// to use addtional things like the domain or the port
    ///
    /// # Example
    ///
    /// ```
    /// # use url::Url;
    /// # use minkan_client::server::Server;
    /// # use minkan_client::Application;
    /// # tokio_test::block_on(async {
    /// let app = Application::new("sqlite::memory:").await.unwrap();
    /// let api_endpoint = Url::parse("https://example.com/graphql").unwrap();
    /// let server = Server::new(api_endpoint, None, app).await.unwrap();
    /// assert_eq!(server.endpoint().path(), "/graphql");
    /// # })
    /// ```
    pub fn endpoint(&self) -> &Url {
        &self.api_endpoint
    }

    /// Returns the nickname user-defined nickname of a [`Server`].
    /// Nicknames can help a user to identify a [`Server`] easier.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use url::Url;
    /// # use minkan_client::server::Server;
    /// # use minkan_client::Application;
    /// # tokio_test::block_on(async {
    /// let app = Application::new("sqlite::memory:").await.unwrap();
    /// let api_endpoint = Url::parse("https://example.com/graphql").unwrap();
    /// let nickname = Some("my friend's minkan instance".to_string());
    /// let server = Server::new(api_endpoint, nickname, app).await.unwrap();
    /// assert!(server.nickname().is_some());
    /// # })
    pub fn nickname(&self) -> &Option<String> {
        &self.nickname
    }
}

impl Server {
    /// Shortcut for database operations so they dont have to use `new`
    pub(crate) fn from_values(
        endpoint: impl AsRef<str>,
        nickname: Option<String>,
        app: Application,
    ) -> Result<Self> {
        Ok(Self {
            api_endpoint: Url::parse(endpoint.as_ref()).map_err(|e| Error::ParseError(e.into()))?,
            nickname,
            app,
        })
    }
}
