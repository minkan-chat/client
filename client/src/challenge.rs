//! Proof the ownership of a key to a [`Server`]
use bytes::Bytes;
use graphql_client::{GraphQLQuery, QueryBody};

use crate::{server::Server, util::perform_query, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
#[non_exhaustive]
/// A random challenge used by the [`crate::server::Server`] to ensure that the
/// [`crate::actor::Actor`] has control over the primary key of a [`sequoia_openpgp::Cert`]
pub struct Challenge {
    /// The actual challenge hex string
    challenge: Bytes,
}

impl Challenge {
    /// Request a [`Challenge`] from a [`Server`]
    ///
    /// # Example
    ///
    /// Note: This example is not tested because it needs a running backend server
    /// ```ignore
    /// # use url::Url;
    /// # use minkan_client::server::Server;
    /// # use minkan_client::Application;
    /// # use minkan_client::challenge::Challenge;
    /// # tokio_test::block_on( async {
    /// let api_endpoint = Url::parse("http://localhost:8000/graphql").unwrap();
    ///
    /// // the server we request the challange from
    /// let server = Server::new(api_endpoint, None).await.unwrap();
    ///
    /// let challenge = Challenge::request(&server).await.unwrap();
    ///
    /// // and you can compare them (but they should never be the same anyway)
    /// assert!(challenge == challenge);
    ///
    /// # })
    /// ```
    pub async fn request(server: &Server) -> Result<Self> {
        perform_query::<Self>(Self::build_query(()), server).await
    }
}

impl GraphQLQuery for Challenge {
    type Variables = ();
    type ResponseData = Self;
    fn build_query(variables: Self::Variables) -> QueryBody<Self::Variables> {
        QueryBody {
            variables,
            query: include_str!("../../other/graphql/queries/get_challenge.graphql"),
            operation_name: "getChallenge",
        }
    }
}
