use crate::models::{error::SignupError, user::UnregisteredUser, User};
use graphql_client::{GraphQLQuery, QueryBody};
use serde::Serialize;

crate::deserializable_result_type! {
    #[non_exhaustive]
    #[derive(Debug)],
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
