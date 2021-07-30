use bytes::Bytes;
use graphql_client::{GraphQLQuery, Response};
use reqwest;
use serde_cbor;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.graphql",
    query_path = "user_query.graphql",
    response_derives = "Debug"
)]
pub struct FindUserByName;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Binary(Bytes);

pub async fn find_user_by_name(variables: find_user_by_name::Variables) -> Result<(), Box<dyn std::error::Error>> {
    let request_body = FindUserByName::build_query(variables);
   
    let request_body = serde_cbor::to_vec(&request_body).unwrap();
    let client = reqwest::blocking::Client::new();
    let res = client.post("http://127.0.0.1:8000/graphql").body(reqwest::blocking::Body::from(request_body)).send()?;
    let response_body: Response<find_user_by_name::ResponseData> = serde_cbor::from_slice(&res.bytes().expect("Failed to get bytes").to_vec()).expect("Failed to parse cbor");
    println!("{:#?}", response_body);
    Ok(())
}