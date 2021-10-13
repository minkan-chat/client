//! Data storage and different database backends

#[cfg(target_arch = "wasm")]
pub mod indexed_db;
#[cfg(not(target_arch = "wasm"))]
pub mod sqlite;
/// A database that will be used to store application data
///
/// This struct is used to abstract different database backends
// Usually, you probably want to use a trait for this but since async traits
// and especially streams in async traits are really not a real thing and we
// don't expose this struct, it's okay to just use different implementations
// on different backends (see [`self::indexed_db`] and [`self::sqlite`])
#[derive(Debug)]
pub struct Database {
    #[cfg(not(target_arch = "wasm32"))]
    db: sqlx::SqlitePool,
    #[cfg(target_arch = "wasm32")]
    // guess thats the right thing?
    db: web_sys::IdbOpenDbRequest,
}
