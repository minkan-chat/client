use graphql_client::{GraphQLQuery, QueryBody, Response};

pub(crate) mod mutations;
pub(crate) mod queries;

use lazy_static::lazy_static;
use reqwest::{Body, Client, ClientBuilder};

pub(crate) async fn perform_query<T: GraphQLQuery>(
    query_body: QueryBody<T::Variables>,
) -> Response<T::ResponseData> {
    lazy_static! {
        static ref CLIENT: Client = ClientBuilder::new().build().unwrap();
    };

    let query_body = serde_cbor::to_vec(&query_body).unwrap();
    let res = CLIENT
        .post("http://127.0.0.1:8000/graphql")
        .body(Body::from(query_body))
        .header("Content-Type", "application/octet-stream")
        .send()
        .await
        .unwrap();
    let response_body: Response<T::ResponseData> =
        serde_cbor::from_slice(&res.bytes().await.unwrap()).unwrap();
    response_body
}
