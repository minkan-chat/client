use crate::models::{
    error::{AuthenticationError, SignupError},
    user::{UnauthenticatedUser, UnregisteredUser},
    User,
};
use graphql_client::{GraphQLQuery, QueryBody};
use serde::Serialize;

crate::deserializable_result_type! {
    #[non_exhaustive],
    pub struct Signup {
        pub result: Result<User, Vec<SignupError>>,
    },
    "signup",
    user,
}

#[derive(Serialize)]
pub struct SignupUserInput {
    pub user: UnregisteredUser,
}

impl GraphQLQuery for Signup {
    type Variables = SignupUserInput;
    type ResponseData = Self;
    fn build_query(variables: Self::Variables) -> graphql_client::QueryBody<Self::Variables> {
        QueryBody {
            variables,
            query: include_str!("../../../other/graphql/mutations/signup.graphql"),
            operation_name: "signup",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuthenticationCredentialsUserInput {
    pub credentials: UnauthenticatedUser,
}

crate::deserializable_result_type! {
    #[non_exhaustive],
    pub struct Authenticate {
        pub result: Result<User, Vec<AuthenticationError>>,
    },
    "authenticate",
    user
}

impl GraphQLQuery for Authenticate {
    type Variables = AuthenticationCredentialsUserInput;
    type ResponseData = Self;
    fn build_query(variables: Self::Variables) -> QueryBody<Self::Variables> {
        QueryBody {
            variables,
            operation_name: "authenticate",
            query: include_str!("../../../other/graphql/mutations/authenticate.graphql"),
        }
    }
}
