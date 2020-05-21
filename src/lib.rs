#[macro_use]
extern crate lazy_static;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod error;

pub mod pe;
