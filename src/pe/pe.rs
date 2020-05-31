use crate::error;
use crate::pe::header::Headers;
use crate::pe::section::ImportDirectoryTable;
use scroll::Pread;
use serde::{Deserialize, Serialize};

#[allow(unused)]
use crate::pe::display;

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct PE {
    pub headers: Headers,
    pub import_directory_table: ImportDirectoryTable,
}

impl PE {
    pub fn new(bytes: &[u8]) -> error::Result<Self> {
        let headers:Headers = Headers::parse(&bytes)?;
        let import_directory_table_offset:usize = headers.clone().get_imports_offset().unwrap();
        let import_directory_table:ImportDirectoryTable = bytes.pread_with::<ImportDirectoryTable>(import_directory_table_offset, scroll::LE)?;

        Ok(PE {
            headers,
            import_directory_table
        })
    }
}

