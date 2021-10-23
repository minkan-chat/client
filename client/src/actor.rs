//! Keeps the different types of actors that can appear

use std::fmt::Debug;

use downcast_rs::{impl_downcast, Downcast};
use sequoia_openpgp::Cert;

mod user;

use crate::{seal::Sealed, Node};
#[doc(inline)]
pub use user::User;

// GraphQL tags interfaces (traits in rust) with `__typename`
#[typetag::serde(tag = "__typename")]
/// Everything that can take actions implements the [`Actor`] trait.
pub trait Actor: Sealed + Downcast + Node + Debug {
    /// The openpgp certificate of an [`Actor`] from `sequoia-openpgp`
    fn certificate(&self) -> &Cert;
    /// The name of an [`Actor`] used to identify them
    fn name(&self) -> &str;
}
// actor types support downcasting
impl_downcast!(Actor);
