use graphql_client::{GraphQLQuery, QueryBody};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[non_exhaustive]
/// A GraphQL query to get a challenge used for signup
pub struct GetChallenge {
    // since the schema for this query is
    // ```graphql
    // getChallenge: String!
    // ```
    // it returns ``{ "getChallenge": "xxx" } ``, which doesn't look so good, just ``challenge`` looks better imo
    #[serde(rename = "getChallenge")]
    pub challenge: String,
}

impl GraphQLQuery for GetChallenge {
    // we have no variables
    type Variables = ();
    type ResponseData = Self;
    fn build_query(_: Self::Variables) -> QueryBody<Self::Variables> {
        QueryBody {
            variables: (),
            query: include_str!("../../../other/graphql/queries/get_challenge.graphql"),
            operation_name: "getChallenge",
        }
    }
}
