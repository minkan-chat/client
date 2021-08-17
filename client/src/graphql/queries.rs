use graphql_client::GraphQLQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../other/graphql/schema.graphql",
    query_path = "../other/graphql/queries.graphql",
    response_derives = "Debug"
)]
pub(crate) struct GetChallenge;
