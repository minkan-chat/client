use uuid::Uuid;

use crate::seal::Sealed;

/// This represents the `Node` interface as defined in the [graphql best practice][1]
/// Basically, this is everything that has an unique identifier
///
/// [1]: https://graphql.org/learn/global-object-identification/#node-interface
pub trait Node: Sealed {
    /// The unique identifer of this [`Node`]
    fn id(&self) -> &Uuid;
}
