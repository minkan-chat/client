/// [Sealing traits][1]
///
/// [Trait sealing][1] prevents implementations of a trait outside this crate.
/// This allows future extensions for a trait without a breaking change.
///
/// [1]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait Sealed {}
