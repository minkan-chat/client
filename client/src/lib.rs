//! A wasm compatible client implementation for the [minkan server](https://github.com/minkan-chat/server)
//!
//! For native builds, SQLite is used. For wasm builds, indexedDB is used.
#![warn(missing_docs, missing_debug_implementations)]
#![feature(generic_associated_types, type_alias_impl_trait)]
pub mod database;
pub(crate) mod seal;

pub mod actor;
mod application;
mod error;

pub mod server;

#[doc(inline)]
pub use application::Application;
#[doc(inline)]
pub use error::{Error, Result};
