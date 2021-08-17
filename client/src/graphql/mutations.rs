use graphql_client::GraphQLQuery;

use crate::models::scalars::Bytes;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../other/graphql/schema.graphql",
    query_path = "../other/graphql/mutations.graphql",
    response_derives = "Debug"
)]
pub(crate) struct Signup;
