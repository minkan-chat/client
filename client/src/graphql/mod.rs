use graphql_client::{GraphQLQuery, QueryBody, Response};

pub mod mutations;
pub mod queries;

use lazy_static::lazy_static;
use reqwest::{Body, Client, ClientBuilder};

pub(crate) async fn perform_query<T: GraphQLQuery>(
    query_body: QueryBody<T::Variables>,
) -> anyhow::Result<Response<T::ResponseData>> {
    lazy_static! {
        static ref CLIENT: Client = ClientBuilder::new().build().unwrap();
    };

    let query_body = serde_cbor::to_vec(&query_body).unwrap();
    let res = CLIENT
        .post("http://127.0.0.1:8000/graphql") // TODO: don't hardcode this!
        .body(Body::from(query_body))
        .header("Content-Type", "application/octet-stream")
        .send()
        .await?;
    Ok(serde_cbor::from_slice(&res.bytes().await?)?)
}

#[macro_export]
// big thanks to Stu!! (https://github.com/Stupremee)
/// This macro is to create deserializable result types from the GraphQL response.
/// A graphql query/mutation is considered successful if there were no errors.
///
/// # Example
///
/// This creates a struct for this graphql:
/// ```graphql
/// mutation signup($user: SignupUserInput) {
///     signup(user: $user) {
///         user {
///             id
///             name
///             certificate {
///                 fingerprint
///                 content
///             }
///             token {
///                 accessToken
///                 refreshToken
///             }
///         }
///         errors {
///             ... on Error {
///                 __typename
///                 description
///             }
///         }
///     }
/// }
/// ```
///
/// where ``AuthenticatedUser`` holds the ``user`` in the response and ``Vec<SignupError>`` a (this)error enum:
/// ```rust
/// # use minkan_client::deserializable_result_type;
/// # use minkan_client::models::User as AuthenticatedUser;
/// # use minkan_client::models::error::SignupError;
/// # use serde::Serialize;
/// # use minkan_client::models::user::UnregisteredUser;
/// # use graphql_client::{GraphQLQuery, QueryBody};
///
/// deserializable_result_type! {
///     #[derive(Debug)],
///     pub struct Signup {
///         pub result: Result<AuthenticatedUser, Vec<SignupError>>,
///     },
///     "signup", // this is the same as the operation_name in the GraphQLQuery trait implementation
///     user,
/// }
///
/// // You can then implement or derive the [``graphql_client::GraphQLQuery``] on the generated ``Signup`` struct for serialization:
///
/// #[derive(Serialize)]
/// pub struct SignupUserInput {
///     pub user: UnregisteredUser,
/// }
///
/// impl GraphQLQuery for Signup {
///     type Variables = SignupUserInput;
///     type ResponseData = Self;
///     fn build_query(variables: Self::Variables) -> graphql_client::QueryBody<Self::Variables> {
///         QueryBody {
///             variables: variables,
///             query: include_str!("../../../other/graphql/mutations/signup.graphql"), // the actual query (see first code block)
///             operation_name: "signup",
///         }
///     }
/// }
/// ```
macro_rules! deserializable_result_type {
    (
        $(#[$attr:meta])*,
        $pub:vis struct $name:ident {
            $res_v:vis $field:ident: Result<$ok:ty, Vec<$err:ty>>,
        },
        $result_name:literal,
        $ok_field:ident $(,)?
    ) => {
        $(#[$attr])*
        $pub struct $name {
            $res_v $field: $crate::__private::std::result::Result<$ok, $crate::__private::std::vec::Vec<$err>>,
        }

        impl<'de> $crate::__private::serde::de::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> $crate::__private::std::result::Result<Self, D::Error>
            where
                D: $crate::__private::serde::Deserializer<'de>,
            {
                #[derive($crate::__private::serde::Deserialize, $crate::__private::std::fmt::Debug)]
                struct Repr {
                    #[serde(rename = $result_name)]
                    field: InnerRepr,
                }

                #[derive($crate::__private::serde::Deserialize, $crate::__private::std::fmt::Debug)]
                struct InnerRepr {
                    $ok_field: $crate::__private::std::option::Option<$ok>,
                    errors: $crate::__private::std::vec::Vec<$err>,
                }

                let repr = <Repr as $crate::__private::serde::Deserialize>::deserialize(deserializer)?;

                let result = match repr.field.errors.is_empty() {
                    true => $crate::__private::std::result::Result::Ok(repr.field.$ok_field.unwrap()),
                    false => $crate::__private::std::result::Result::Err(repr.field.errors),
                };

                $crate::__private::std::result::Result::Ok($name { $field: result })
            }
        }
    };
}
