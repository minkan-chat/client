use crate::{seal::Sealed, Node};

use super::Actor;
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
/// Represents a real person using the application
pub struct User {
    id: Uuid,
    name: String,
    #[serde(
        rename = "certificate",
        serialize_with = "crate::serialize_cert",
        deserialize_with = "crate::deserialize_cert"
    )]
    cert: Cert,
}

impl Sealed for User {}

impl Node for User {
    fn id(&self) -> &Uuid {
        &self.id
    }
}

#[typetag::serde]
impl Actor for User {
    fn certificate(&self) -> &Cert {
        &self.cert
    }

    fn name(&self) -> &str {
        &self.name
    }
}
