//! Helper methods

use graphql_client::{GraphQLQuery, QueryBody, Response};
use sequoia_openpgp::{parse::Parse, serialize::SerializeInto, Cert};
use serde::{Deserialize, Deserializer, Serializer};
use std::result::Result as StdResult;

use crate::{server::Server, Error, Result};

/// A helper method to serialize a [`Cert`] with serde.
///
/// **This method will always include secret key material if there is some**
pub fn serialize_cert<S>(cert: &Cert, ser: S) -> StdResult<S::Ok, S::Error>
where
    S: Serializer,
{
    ser.serialize_bytes(
        &cert
            .as_tsk()
            .export_to_vec()
            .map_err(<S::Error as serde::ser::Error>::custom)?,
    )
}

/// A helper method to deserialize a [`Cert`] with serde
pub fn deserialize_cert<'de, D>(de: D) -> StdResult<Cert, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    // this represents the `certificate` field in an [`crate::actor::Actor`]
    #[serde(rename = "certificate")]
    struct Repr {
        body: bytes::Bytes,
    }
    let repr = Repr::deserialize(de)?;

    Cert::from_bytes(&repr.body).map_err(<D::Error as serde::de::Error>::custom)
}

/// A helper method to deserialize a [`Cert`] with serde which returns a [`Box`]
pub fn deserialize_cert_box<'de, D>(de: D) -> StdResult<Box<Cert>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_cert::<'de>(de).map(Box::new)
}

/// Performs a graphql query/mutation
pub async fn perform_query<T>(
    query_body: QueryBody<T::Variables>,
    server: &Server,
) -> Result<T::ResponseData>
where
    T: GraphQLQuery,
{
    // there shouldn't be an error with serde
    let body = serde_cbor::to_vec(&query_body).map_err(|e| Error::Other(e.into()))?;

    // perform the request
    let response = server
        .client
        .post(server.api_endpoint.clone())
        // cbor is in application/octet-stream
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .send()
        .await?;

    let response: Response<T::ResponseData> =
        serde_cbor::from_slice(&response.bytes().await?).map_err(|e| Error::Other(e.into()))?;

    /*
    A GraphQL response looks like the following:
    {
        "data": expected data (T::ResponseData),
        "errors": Vec<errors as defined in the graphql spec>
    }
    graphql_client represents that with the Response<T::ResponseData> struct,
    where both data and errors are Options
    */
    // if data is None, there must be at least one error (at least as defined in the graphql spec)
    response.data.ok_or(()).or_else(|_| {
        //
        response
            .errors
            // no data and no errors violates the spec
            .ok_or_else(|| anyhow::anyhow!("api did not return any data nor any errors").into())
            // map in erros from Some into Err since we handle them in the Result type as GraphQL errors
            .and_then(|errors| Err(Error::GraphQLError(errors)))
    })
}
