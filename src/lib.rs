// Allow dead code during incremental module development — types, structs, and
// functions are defined ahead of their callers across multiple build phases.
#![allow(dead_code)]

pub mod error;
pub mod tokens;
pub(crate) mod types;
pub mod context;
pub(crate) mod preprocessor;
pub(crate) mod formats;
pub(crate) mod runtime_lib;
pub mod tools;
pub use error::{TccError, TccResult};
pub use context::{TccContext, OutputType};
