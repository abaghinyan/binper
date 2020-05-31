//! [![](http://meritbadge.herokuapp.com/binper)](https://crates.io/crates/binper)
//! [![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
//! ![](https://img.shields.io/badge/unsafe-forbidden-success.svg)
//! 
//! ## Description
//! BINPER is a binary parser library in Rust.
//! 
//! 🔒 Implemented using 100% safe rust and works on all platforms supported by rust
//! 
//! ## Install
//! ```bash
//! cargo install binper
//! ```
//! ## Binary usage
//! ```bash
//! binper [BIN_FILE_PATH]
//! ```
//! #### ⚠️ WARNING  ⚠️
//! Currently, only PE file parsing is implemented
//! 
//! ## Library usage
//! ```rust
//! use std::fs::File;
//! use std::io::Read;
//! 
//! use binper::pe::pe::PE;
//! 
//! fn main() -> binper::error::Result<()> {
//!     let mut f = File::open("samples/pe.exe")?;
//!     let mut data = Vec::new();
//!     f.read_to_end(&mut data)?;
//!     let pe:PE = PE::new(&data)?;
//!     println!("{}", pe);
//! 
//!     Ok(())
//! }
//! ```
//! 
//! ## Progress
//! Windows binary PE
//! - [x] DOS header
//! - [x] PE header
//! - [x] Optional header
//! - [x] Data Directories
//! - [x] Sections
//! - [ ] Export, Import tables
//! - [ ] Resources
//! 
//! Linux binary ELF
//! - [ ] ELF header
//! - [ ] Program header table
//! - [ ] Sections
//! 
//! ## Contribution
//! If you want to add some features, fix bugs or improve the code as defined in the MIT license, without any additional terms or conditions,
//! I will gladly accept.
//! 
//! ## ⚠️ WARNING  ⚠️
//! This is an alpha version.
//! I don't recommend you to use in your production applications.
//! The structure of objects can change.
//! 
//! ## License
//! 
//! `binper` is distributed under the terms of the MIT license.
//! 
//! See [LICENSE](./LICENSE) for
//! details.

#[macro_use]
extern crate lazy_static;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod error;

pub mod pe;
